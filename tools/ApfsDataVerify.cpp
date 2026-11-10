// SPDX-License-Identifier: GPL-2.0-or-later
// Reuse the unchanged, pinned read-only extractor at the new volume root.
#define main original_data_inventory_main
#include "ApfsDataInventory.cpp"
#undef main
#include <ApfsLib/Util.h>

static std::string uuidHex(const apfs_uuid_t &uuid) {
  return hex(std::vector<uint8_t>(std::begin(uuid), std::end(uuid)));
}

int main(int argc, char **argv) {
  try {
    need(argc == 3, "Usage: apfs-data-verify regular-Data-image new-empty-blob-directory");
    struct stat input{}, output{};
    need(!lstat(argv[1], &input) && S_ISREG(input.st_mode), "Source must be a regular image");
    need(!lstat(argv[2], &output) && S_ISDIR(output.st_mode), "Blob directory must be local");
    std::unique_ptr<Device> device(Device::OpenDevice(argv[1]));
    need(bool(device), "Cannot open Data image read-only");
    std::vector<uint8_t> header(4096);
    need(device->Read(header.data(), 0, header.size()) && VerifyBlock(header.data(), header.size()), "Invalid container checksum");
    const auto &nx = *reinterpret_cast<const nx_superblock_t *>(header.data());
    need(nx.nx_magic == NX_MAGIC && nx.nx_block_size == 4096 && nx.nx_block_count == uint64_t(input.st_size) / 4096 &&
         nx.nx_features == 0 && nx.nx_readonly_compatible_features == 0 && nx.nx_incompatible_features == 2,
         "Container format/features differ from the bounded APFS v2 format");
    unsigned volumes = 0;
    for (const auto &oid : nx.nx_fs_oid) volumes += oid != 0;
    need(volumes == 1, "Expected one Data volume");
    ApfsContainer container(device.get(), 0, device->GetSize());
    need(container.Init(), "Cannot initialize Data container");
    apfs_superblock_t sb{};
    need(container.GetVolumeInfo(0, sb), "Cannot inspect Data volume");
    need(sb.apfs_role == 0 && sb.apfs_fs_flags == APFS_FS_UNENCRYPTED && sb.apfs_features == APFS_FEATURE_HARDLINK_MAP_RECORDS &&
         sb.apfs_readonly_compatible_features == 0 && sb.apfs_incompatible_features == APFS_INCOMPAT_NORMALIZATION_INSENSITIVE,
         "Unexpected Data role, encryption or feature bits");
    std::unique_ptr<ApfsVolume> volume(container.GetVolume(0));
    need(bool(volume) && std::string(volume->name()) == "Data", "Cannot read named Data volume");
    std::printf("{\"kind\":\"volume\",\"container_uuid_hex\":\"%s\",\"volume_uuid_hex\":\"%s\",\"block_bytes\":4096,\"bytes\":%llu,\"role\":0,\"unencrypted\":true,\"case_sensitive\":true,\"normalization_insensitive\":true,\"container_incompatible_features\":2,\"volume_features\":2,\"volume_incompatible_features\":8}\n",
                uuidHex(nx.nx_uuid).c_str(), uuidHex(sb.apfs_vol_uuid).c_str(), static_cast<unsigned long long>(input.st_size));
    ApfsDir directory(*volume);
    // A nonempty prefix makes Inventory visit every child, including any
    // unexpected staged_system_apps directory. The caller removes "Data/".
    Inventory inventory(directory, argv[2]); inventory.walk(2, "Data", 0);
    std::fprintf(stderr, "Read back Data: %u entries, %u streams, %llu logical bytes\n", inventory.nodes, inventory.files,
                 static_cast<unsigned long long>(inventory.totalBytes));
    return 0;
  } catch (const std::exception &error) { std::fprintf(stderr, "%s\n", error.what()); return 1; }
}
