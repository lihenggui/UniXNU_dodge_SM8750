// SPDX-License-Identifier: GPL-2.0-or-later
// Read the stock initial Data tree without mounting, following symlinks or chowning host files.
#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/ApfsVolume.h>
#include <ApfsLib/ApfsDir.h>
#include <ApfsLib/Decmpfs.h>
#include <ApfsLib/Device.h>
#include <ApfsLib/GptPartitionMap.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

// The pinned reader declares this plain metadata constructor without defining it.
// Initialize only the public fields; do not modify the pinned library source.
ApfsDir::XAttr::XAttr() : flags(0), xdata_len(0), xstrm{} {}

static void need(bool good, const std::string &message) { if (!good) throw std::runtime_error(message); }
static std::string quote(const std::string &value) {
  const char *digits = "0123456789abcdef"; std::string out = "\"";
  for (unsigned char c : value) {
    if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
    else if (c < 32) { out += "\\u00"; out += digits[c >> 4]; out += digits[c & 15]; }
    else out += char(c);
  }
  return out + '"';
}
static std::string hex(const std::vector<uint8_t> &bytes) {
  const char *digits = "0123456789abcdef"; std::string out; out.reserve(bytes.size() * 2);
  for (auto c : bytes) { out += digits[c >> 4]; out += digits[c & 15]; } return out;
}

struct Inventory {
  ApfsDir &directory;
  std::string destination;
  Inventory(ApfsDir &reader, const std::string &path) : directory(reader), destination(path) {}
  unsigned nodes = 0, files = 0;
  uint64_t totalBytes = 0, attributeBytes = 0;
  std::unordered_set<uint64_t> visitedDirectories;
  std::map<uint64_t, std::pair<std::string, uint64_t>> blobs;
  static constexpr uint64_t maxFile = 256ULL << 20, maxTotal = 512ULL << 20, maxAttribute = 4ULL << 20;

  std::vector<uint8_t> attribute(uint64_t inode, const std::string &name) {
    need(!name.empty() && name.size() < 1024 && name.find('\0') == std::string::npos, "Invalid extended attribute name");
    ApfsDir::XAttr info{}; need(directory.GetAttributeInfo(info, inode, name.c_str()), "Cannot inspect extended attribute");
    if (info.flags & XATTR_DATA_STREAM) {
      need(info.xstrm.dstream.size <= maxAttribute && info.xstrm.dstream.alloced_size <= maxAttribute &&
           info.xstrm.dstream.size <= info.xstrm.dstream.alloced_size, "Extended attribute exceeds bound");
    } else need(info.flags & XATTR_DATA_EMBEDDED, "Unsupported extended attribute storage");
    std::vector<uint8_t> data; need(directory.GetAttribute(data, inode, name.c_str()), "Cannot read extended attribute");
    need(data.size() <= maxAttribute && attributeBytes <= (64ULL << 20) - data.size(), "Extended attribute inventory exceeds bound");
    attributeBytes += data.size(); return data;
  }

  std::pair<std::string, uint64_t> content(const ApfsDir::Inode &info, const std::map<std::string, std::vector<uint8_t>> &attrs) {
    const auto existing = blobs.find(info.obj_id); if (existing != blobs.end()) return existing->second;
    uint64_t length = info.ds_size; const bool compressed = info.bsd_flags & 0x20U;
    need(length <= maxFile && info.uncompressed_size <= maxFile, "Initial Data file exceeds bound");
    std::vector<uint8_t> decoded;
    if (compressed) {
      const auto it = attrs.find("com.apple.decmpfs"); need(it != attrs.end() && it->second.size() >= 16, "Missing compression header");
      const auto *header = reinterpret_cast<const CompressionHeader *>(it->second.data());
      need(uint64_t(header->size) <= maxFile && IsDecompAlgoSupported(header->algo), "Unsupported or oversized compressed Data file");
      need(DecompressFile(directory, info.obj_id, decoded, it->second), "Cannot decode initial Data file");
      length = decoded.size(); need(length == header->size && length <= maxFile, "Decoded Data file length differs");
    }
    need(length <= maxTotal && totalBytes <= maxTotal - length, "Initial Data total exceeds bound");
    const std::string name = "inode-" + std::to_string(info.obj_id);
    int fd = open((destination + '/' + name).c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    need(fd >= 0, "Blob output must be new"); bool good = true;
    std::vector<uint8_t> buffer(1U << 20);
    for (uint64_t offset = 0; good && offset < length;) {
      size_t count = size_t(std::min<uint64_t>(buffer.size(), length - offset)); const uint8_t *data;
      if (compressed) data = decoded.data() + offset;
      else if (directory.ReadFile(buffer.data(), info.private_id, offset, count)) data = buffer.data();
      else { good = false; break; }
      for (size_t done = 0; done < count;) {
        ssize_t n = write(fd, data + done, count - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { good = false; break; }
        done += size_t(n);
      }
      offset += count;
    }
    if (close(fd)) good = false;
    need(good, "Failed to extract initial Data bytes"); totalBytes += length; ++files;
    return blobs.emplace(info.obj_id, std::make_pair(name, length)).first->second;
  }

  void walk(uint64_t inode, const std::string &path, unsigned depth) {
    need(depth <= 64 && ++nodes <= 100000 && path.size() < 4096, "Initial Data traversal exceeds bound");
    ApfsDir::Inode info; need(directory.GetInode(info, inode), "Cannot read initial Data inode: " + path);
    // apfs-fuse supplies the inode identity separately from its private stream id.
    need(info.obj_id == inode, "Initial Data inode identity differs");
    const bool dir = S_ISDIR(info.mode), file = S_ISREG(info.mode), link = S_ISLNK(info.mode);
    need(dir || file || link, "Unsupported initial Data inode type: " + path);
    std::vector<std::string> names; need(directory.ListAttributes(names, inode) && names.size() <= 128, "Cannot list extended attributes");
    std::sort(names.begin(), names.end()); need(std::adjacent_find(names.begin(), names.end()) == names.end(), "Duplicate extended attribute");
    std::map<std::string, std::vector<uint8_t>> attrs;
    for (const auto &name : names) attrs.emplace(name, attribute(inode, name));
    std::string body = "{\"path\":" + quote(path) + ",\"inode\":" + std::to_string(inode) +
      ",\"type\":" + quote(dir ? "directory" : file ? "file" : "symlink") +
      ",\"mode\":" + std::to_string(info.mode) + ",\"uid\":" + std::to_string(info.owner) +
      ",\"gid\":" + std::to_string(info.group) + ",\"bsd_flags\":" + std::to_string(info.bsd_flags) +
      ",\"protection_class\":" + std::to_string(info.default_protection_class) +
      ",\"create_time_ns\":" + std::to_string(info.create_time) + ",\"mod_time_ns\":" + std::to_string(info.mod_time) +
      ",\"access_time_ns\":" + std::to_string(info.access_time) + ",\"change_time_ns\":" + std::to_string(info.change_time);
    if (file) {
      const auto blob = content(info, attrs);
      body += ",\"blob\":" + quote(blob.first) + ",\"bytes\":" + std::to_string(blob.second) +
              ",\"decompressed\":" + std::string(info.bsd_flags & 0x20U ? "true" : "false");
    } else if (link) {
      const auto target = attrs.find("com.apple.fs.symlink"); need(target != attrs.end(), "Missing symbolic link attribute");
      auto bytes = target->second; if (!bytes.empty() && bytes.back() == 0) bytes.pop_back();
      need(!bytes.empty() && bytes.size() < 4096 && std::find(bytes.begin(), bytes.end(), 0) == bytes.end(), "Invalid symbolic link payload");
      body += ",\"target\":" + quote(std::string(bytes.begin(), bytes.end()));
    }
    body += ",\"xattrs_hex\":{"; bool first = true;
    for (const auto &attr : attrs) { if (!first) body += ','; first = false; body += quote(attr.first) + ':' + quote(hex(attr.second)); }
    body += "}}"; std::puts(body.c_str());
    if (!dir) return;
    need(visitedDirectories.insert(inode).second, "Cyclic or multiply linked Data directory");
    std::vector<ApfsDir::DirRec> children; need(directory.ListDirectory(children, inode), "Cannot list initial Data directory");
    need(children.size() <= 100000, "Initial Data directory exceeds bound");
    std::sort(children.begin(), children.end(), [](const auto &a, const auto &b) { return a.name < b.name; });
    std::string previous;
    for (const auto &child : children) {
      need(!child.name.empty() && child.name != "." && child.name != ".." && child.name.find('/') == std::string::npos &&
           child.name.find('\0') == std::string::npos && child.name != previous, "Invalid or duplicate initial Data name");
      previous = child.name;
      if (path.empty() && child.name == "staged_system_apps") continue;
      walk(child.file_id, path.empty() ? child.name : path + '/' + child.name, depth + 1);
    }
  }
};

int main(int argc, char **argv) {
  try {
    need(argc == 3, "Usage: apfs-data-inventory regular-OS-image new-empty-blob-directory");
    struct stat input{}, output{};
    need(!lstat(argv[1], &input) && S_ISREG(input.st_mode), "Source must be a regular image");
    need(!lstat(argv[2], &output) && S_ISDIR(output.st_mode), "Blob directory must be a local directory");
    std::unique_ptr<Device> device(Device::OpenDevice(argv[1])); need(bool(device), "Cannot open source image read-only");
    uint64_t offset = 0, size = device->GetSize(); GptPartitionMap gpt;
    if (gpt.LoadAndVerify(*device)) {
      const int index = gpt.FindFirstAPFSPartition(); need(index >= 0, "OS image has no APFS partition");
      gpt.GetPartitionOffsetAndSize(index, offset, size);
    }
    ApfsContainer container(device.get(), offset, size); need(container.Init(), "Cannot initialize source APFS reader");
    std::unique_ptr<ApfsVolume> volume(container.GetVolume(0)); need(bool(volume), "Cannot read original OS volume");
    ApfsDir directory(*volume); uint64_t inode = 2;
    for (const char *part : {"private", "var"}) {
      ApfsDir::DirRec entry; need(directory.LookupName(entry, inode, part), "Original initial Data path absent"); inode = entry.file_id;
    }
    Inventory inventory(directory, argv[2]); inventory.walk(inode, "", 0);
    std::fprintf(stderr, "Read-only initial Data: %u entries, %u unique file streams, %llu bytes\n", inventory.nodes, inventory.files,
                 static_cast<unsigned long long>(inventory.totalBytes));
    return 0;
  } catch (const std::exception &error) { std::fprintf(stderr, "%s\n", error.what()); return 1; }
}
