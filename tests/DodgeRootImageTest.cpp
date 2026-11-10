// SPDX-License-Identifier: BSD-2-Clause-Patent
// Execute the real UFS consumers against regular files behind an in-memory GPT.
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include "RootDiagnostics.h"

using IOReturn = uint32_t;
constexpr IOReturn kIOReturnSuccess = 0, kIOReturnBadArgument = 1, kIOReturnIOError = 2;
constexpr unsigned kDataMax = 131072;
static UfsRootDiagnostics gRootDiagnostic;
static uint8_t header[4096], entries[4096], manifest[4096], original[4096];
static int image = -1;
static uint64_t imageBytes, partitionFirst = 256, partitionLast;
static bool readFailure;

static bool exactRead(int fd, uint64_t offset, void *output, size_t count) {
  auto *bytes = static_cast<uint8_t *>(output);
  while (count) {
    ssize_t n = pread(fd, bytes, count, static_cast<off_t>(offset));
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    offset += static_cast<uint64_t>(n); bytes += n; count -= static_cast<size_t>(n);
  }
  return true;
}

static IOReturn hostRead4k(uint8_t lun, uint64_t lba, uint32_t blocks, void *output) {
  assert(lun == 0 && output && blocks && blocks <= kDataMax / 4096);
  if (readFailure) return kIOReturnIOError;
  if (lba == 1 && blocks == 1) std::memcpy(output, header, 4096);
  else if (lba == 2 && blocks == 1) std::memcpy(output, entries, 4096);
  else {
    if (lba < partitionFirst || lba > partitionLast || blocks > partitionLast - lba + 1) return kIOReturnBadArgument;
    const uint64_t offset = (lba - partitionFirst) * 4096;
    if (offset == 0 && blocks == 1) std::memcpy(output, manifest, 4096);
    else if (!exactRead(image, offset, output, size_t(blocks) * 4096)) return kIOReturnIOError;
  }
  return kIOReturnSuccess;
}

#include "RootLayout.h"
#include "RootWindowRead.h"
#include "RootPublication.h"

static void put32(uint8_t *p, uint32_t value) { for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(value >> (8 * i)); }
static void put64(uint8_t *p, uint64_t value) { for (unsigned i = 0; i < 8; ++i) p[i] = uint8_t(value >> (8 * i)); }
static void record(const char *name) { std::printf("{\"case\":\"%s\",\"result\":\"PASS\"}\n", name); }
static void fixture() {
  std::memset(header, 0, sizeof(header)); std::memset(entries, 0, sizeof(entries));
  std::memcpy(manifest, original, sizeof(manifest)); readFailure = false;
  partitionLast = partitionFirst + imageBytes / 4096 - 1;
  std::memcpy(header, "EFI PART", 8); put32(header + 8, 0x10000); put32(header + 12, 92);
  put64(header + 24, 1); put64(header + 32, partitionLast + 5);
  put64(header + 40, 6); put64(header + 48, partitionLast);
  put64(header + 72, 2); put32(header + 80, 32); put32(header + 84, 128);
  entries[0] = 1; entries[16] = 2;
  put64(entries + 32, partitionFirst); put64(entries + 40, partitionLast);
  for (unsigned i = 0; i < 6; ++i) entries[56 + 2 * i] = "unixnu"[i];
  put32(header + 88, rootCrc32(entries, sizeof(entries)));
  put32(header + 16, rootCrc32(header, 92, true));
}

static int openRegular(const char *path, uint64_t *length = nullptr) {
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); assert(fd >= 0);
  struct stat st{}; assert(!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size > 0);
  if (length) *length = static_cast<uint64_t>(st.st_size);
  return fd;
}

struct ReadOps {
  std::vector<uint8_t> output;
  bool locked = false, partial = false;
  unsigned locks = 0, unlocks = 0, reads = 0;
  void lock() { assert(!locked); locked = true; ++locks; }
  void unlock() { assert(locked); locked = false; ++unlocks; }
  IOReturn read(uint64_t lba, uint32_t blocks, void *out) {
    assert(locked); ++reads; return hostRead4k(0, lba, blocks, out);
  }
  IOReturn verify(uint64_t, const uint8_t *, size_t length) {
    // This read-only transport has no authenticated-root policy enabled.
    assert(locked && length && length <= 4096); return kIOReturnSuccess;
  }
  uint64_t copy(uint64_t offset, const uint8_t *bytes, uint64_t length) {
    assert(locked && offset <= output.size() && length <= output.size() - offset);
    uint64_t count = partial ? length - 1 : length;
    std::memcpy(output.data() + offset, bytes, static_cast<size_t>(count)); return count;
  }
};

static void manifestFault(const char *name, uint32_t status, const std::function<void()> &change, bool rehash = true) {
  fixture(); change(); if (rehash) SHA256(manifest, 4064, manifest + 4064);
  RootLayout result{}; const char *why = nullptr;
  assert(findRootLayout(&result, &why, "unixnu", partitionLast + 5));
  assert(result.manifestStatus == status && result.windows == 0); record(name);
}

int main(int argc, char **argv) {
  assert(argc == 4); image = openRegular(argv[1], &imageBytes);
  assert(!(imageBytes & 4095) && imageBytes / 4096 < UINT32_MAX - partitionFirst - 8);
  assert(exactRead(image, 0, original, sizeof(original))); fixture();
  RootLayout layout{}; const char *why = nullptr;
  assert(findRootLayout(&layout, &why, "unixnu", partitionLast + 5));
  assert(!layout.manifestStatus && layout.windows == 2 && layout.imageBytes == imageBytes);
  assert(!std::strcmp(layout.window[0].name, "OS") && !std::strcmp(layout.window[1].name, "SystemOS"));
  record("actual-image-production-manifest");
  const char *names[] = { layout.window[0].name, layout.window[1].name };
  UfsRootPlan plan{}; assert(ufsBuildRootPlan(names, 2, plan) && plan.count == 2 && plan.order[0] == 1 && plan.order[1] == 0);
  // Instantiate the publication template too, retaining the actual consumer order.
  struct Publish {
    std::vector<unsigned> order;
    bool start(unsigned i) { order.push_back(i); return true; }
    bool wait(unsigned) { return true; }
    void discard(unsigned) { assert(false); }
  } publish;
  auto result = ufsPublishRootWindows(publish, plan);
  assert(result.phase == UfsRootPhase::Complete && result.published == 2 && publish.order == std::vector<unsigned>({1, 0}));
  struct Prepare {
    bool prepare(unsigned) { return true; }
    bool validate() { return true; }
    bool schedule() { return true; }
    void discard(unsigned) { assert(false); }
  } prepare;
  assert(ufsPrepareRootWindows(prepare, 2).phase == UfsRootPhase::Complete);
  record("actual-image-SystemOS-before-OS");
  std::array<uint8_t, kDataMax> bounce{};
  for (unsigned index = 0; index < 2; ++index) {
    const auto &window = layout.window[index]; uint64_t sourceBytes = 0;
    const int source = openRegular(argv[2 + index], &sourceBytes); assert(sourceBytes == window.size);
    const uint64_t absolute = partitionFirst * 4096 + window.offset, blocks = window.size / 512;
    assert(ufsWindowGeometry(absolute, window.size));
    const std::array<std::pair<uint64_t, uint64_t>, 7> samples = {{{0, 1}, {1, 7}, {7, 3}, {8, 257}, {blocks / 2, 17}, {blocks - 1, 1}, {blocks - 17, 17}}};
    unsigned sample = 0;
    for (const auto &range : samples) {
      ReadOps ops; ops.output.resize(static_cast<size_t>(range.second * 512));
      auto read = ufsReadWindow(ops, absolute, window.size, range.first, range.second, bounce.data());
      assert(read.status == kIOReturnSuccess && read.done == range.second * 512 && !ops.locked && ops.locks == 1 && ops.unlocks == 1);
      if (range.second == 257) assert(ops.reads > 1);
      std::vector<uint8_t> expected(ops.output.size()); assert(exactRead(source, range.first * 512, expected.data(), expected.size()));
      assert(ops.output == expected);
      const std::string name = std::string(window.name) + "-production-window-read-" + std::to_string(++sample); record(name.c_str());
    }
    ReadOps refused;
    auto invalid = ufsReadWindow(refused, absolute, window.size, blocks - 1, 2, bounce.data());
    assert(invalid.status == kIOReturnBadArgument && !invalid.done && !refused.locks && !refused.reads);
    record(index ? "SystemOS-EOF-refused-before-I/O" : "OS-EOF-refused-before-I/O");
    readFailure = true; ReadOps failed; failed.output.resize(512);
    auto error = ufsReadWindow(failed, absolute, window.size, 0, 1, bounce.data());
    assert(error.status == kIOReturnIOError && !error.done && failed.unlocks == 1 && !failed.locked);
    readFailure = false; record(index ? "SystemOS-read-failure-unlocks" : "OS-read-failure-unlocks");
    ReadOps partial; partial.partial = true; partial.output.resize(512);
    auto shortCopy = ufsReadWindow(partial, absolute, window.size, 0, 1, bounce.data());
    assert(shortCopy.status == kIOReturnIOError && shortCopy.done == 511 && partial.unlocks == 1 && !partial.locked);
    record(index ? "SystemOS-short-copy-refused" : "OS-short-copy-refused"); close(source);
  }
  manifestFault("manifest-digest-refused", 3, [] { manifest[4064] ^= 1; }, false);
  manifestFault("manifest-image-size-overflow-refused", 4, [] { put64(manifest + 16, UINT64_MAX); });
  manifestFault("manifest-window-overflow-refused", 4, [] { put64(manifest + 24 + 40, UINT64_MAX - 511); });
  manifestFault("manifest-window-overlap-refused", 6, [] { put64(manifest + 24 + 128 + 32, le64(manifest + 24 + 32)); });
  manifestFault("manifest-duplicate-name-refused", 5, [] { std::strcpy(reinterpret_cast<char *>(manifest + 24 + 128), "OS"); });
  manifestFault("manifest-wrong-logical-block-refused", 7, [] { put32(manifest + 24 + 48, 4096); });
  manifestFault("manifest-writable-window-refused", 7, [] { put32(manifest + 24 + 52, 0); });
  manifestFault("manifest-v2-not-supported-refused", 2, [] { put32(manifest + 8, 2); });
  fixture(); RootLayout rejected{};
  assert(!findRootLayout(&rejected, &why, "userdata", partitionLast + 5)); record("no-userdata-fallback");
  fixture(); assert(!findRootLayout(&rejected, &why, "unixnu", partitionLast + 4)); record("short-LUN-refused");
  close(image);
}
