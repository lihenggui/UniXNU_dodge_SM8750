// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exercise the unchanged RamBlock seed/layout/I/O code with the actual APFS inputs.
#include "SparseDisk.h"
#include "SeedDisk.h"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <limits>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

static std::vector<std::string> cases;
static void check(bool ok, const std::string &message) { if (!ok) throw std::runtime_error(message); }
static void pass(const char *name) { cases.emplace_back(name); }
struct Digest {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  Digest() { check(ctx != nullptr, "SHA context"); }
  ~Digest() { EVP_MD_CTX_free(ctx); }
  static void init(Digest &d) { check(EVP_DigestInit_ex(d.ctx, EVP_sha256(), nullptr) == 1, "SHA init"); }
  static void update(Digest &d, const void *p, size_t n) { check(EVP_DigestUpdate(d.ctx, p, n) == 1, "SHA update"); }
  static void final(Digest &d, uint8_t *p) { unsigned n = 0; check(EVP_DigestFinal_ex(d.ctx, p, &n) == 1 && n == 32, "SHA final"); }
};
static std::string hex(const uint8_t *p) {
  const char *digits = "0123456789abcdef"; std::string out;
  for (unsigned i = 0; i < 32; ++i) { out += digits[p[i] >> 4]; out += digits[p[i] & 15]; } return out;
}
static std::vector<uint8_t> readRegular(const char *path) {
  int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK); check(fd >= 0, "open seed");
  struct stat st{}; check(!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size >= 32 && st.st_size <= 0x10000000, "bounded regular seed");
  std::vector<uint8_t> result(size_t(st.st_size)); size_t n = 0;
  while (n < result.size()) { ssize_t got = read(fd, result.data() + n, result.size() - n); check(got > 0, "seed read"); n += size_t(got); }
  check(!close(fd), "seed close"); return result;
}
struct Ops {
  std::vector<uint8_t *> allocations;
  std::vector<uint8_t> buffer;
  uint64_t allocationLimit = std::numeric_limits<uint64_t>::max();
  uint64_t transferLimit = std::numeric_limits<uint64_t>::max();
  explicit Ops(size_t bytes = 1 << 20) : buffer(bytes + 32, 0xcd) {}
  ~Ops() { for (auto p : allocations) free(p); }
  uint8_t *allocate() {
    if (allocations.size() >= allocationLimit) return nullptr;
    auto p = static_cast<uint8_t *>(calloc(1, 4096)); check(p != nullptr, "host page allocation"); allocations.push_back(p); return p;
  }
  uint64_t read(uint64_t at, void *p, uint64_t n) {
    check(at <= buffer.size() - 32 && n <= buffer.size() - 32 - at, "write descriptor bounds");
    n = std::min(n, transferLimit); memcpy(p, buffer.data() + 16 + at, n); return n;
  }
  uint64_t copy(uint64_t at, const void *p, uint64_t n) {
    check(at <= buffer.size() - 32 && n <= buffer.size() - 32 - at, "read descriptor bounds");
    n = std::min(n, transferLimit); memcpy(buffer.data() + 16 + at, p, n); return n;
  }
  void guards() {
    check(std::all_of(buffer.begin(), buffer.begin() + 16, [](auto c) { return c == 0xcd; }) &&
          std::all_of(buffer.end() - 16, buffer.end(), [](auto c) { return c == 0xcd; }), "descriptor canaries");
  }
};
static void put64(std::vector<uint8_t> &b, size_t at, uint64_t value) { memcpy(b.data() + at, &value, 8); }

int main(int argc, char **argv) {
  try {
    check(argc == 4, "usage: data-seed-test packed-data raw-sha256 seed-identity");
    auto input = readRegular(argv[1]);
    uint64_t logical = 0, nonzero = 0;
    check(ramPackedLayout(input.data(), input.size(), &logical) && seedCountNonzero(input.data(), input.size(), &nonzero), "actual packed layout");
    check(logical == (2ULL << 30) || logical == (3ULL << 30), "bounded test capacities"); pass("actual-packed-layout");
    Ops seedOps;
    std::vector<uint64_t> indexes(nonzero ? nonzero : 1);
    std::vector<uint8_t *> pages(nonzero ? nonzero : 1);
    SeedDisk seed; seed.bytes = logical; seed.capacity = nonzero; seed.index = indexes.data(); seed.page = pages.data();
    check(seedImportSparse(seed, input.data(), input.size(), seedOps) && seed.count == nonzero && seed.resident == nonzero * 4096, "compact seed import");
    pass("actual-compact-import");
    const uint64_t extents = ramU64(input.data() + 24); uint64_t cursor = 32 + 16 * extents;
    for (uint64_t i = 0; i < extents; ++i) {
      const uint64_t at = ramU64(input.data() + 32 + i * 16), n = ramU64(input.data() + 40 + i * 16);
      for (uint64_t j = 0; j < n; j += 4096) {
        auto page = seed.find((at + j) / 4096);
        check(page && !memcmp(page, input.data() + cursor + j, 4096), "compact seed page differs");
      }
      cursor += n;
    }
    pass("every-original-nonzero-page");
    Digest sha; std::array<uint8_t, 32> identity{};
    seedIdentity(seed, sha, Digest::init, Digest::update, Digest::final, identity.data());
    check(hex(identity.data()) == argv[3], "actual SeedDisk identity differs from packer"); pass("actual-source-seed-identity");
    for (uint64_t p : {logical / 4096, logical / 4096 + 1, UINT64_MAX}) check(!seed.find(p), "out-of-range compact lookup");
    pass("compact-lookup-boundaries");
    if (logical <= 2ULL << 30) {
      std::vector<uint8_t *> sparsePages(logical / 4096);
      RamSparseDisk disk{sparsePages.data(), logical, 0}; Ops ops;
      check(ramSparseImport(disk, input.data(), input.size(), ops) && disk.resident == seed.resident, "actual volatile import"); pass("actual-volatile-sparse-import");
      Digest full; Digest::init(full); bool oom = false;
      for (uint64_t at = 0; at < logical; at += 1 << 20) {
        check(ramSparseIO(disk, false, at, 1 << 20, ops, oom) == 1 << 20 && !oom, "complete volatile read");
        Digest::update(full, ops.buffer.data() + 16, 1 << 20);
      }
      Digest::final(full, identity.data()); check(hex(identity.data()) == argv[2], "entire actual RAM read differs from raw image"); ops.guards(); pass("entire-logical-image-through-source-read");
      uint64_t hole = 0; while (hole < sparsePages.size() && sparsePages[hole]) ++hole;
      check(hole + 8 < sparsePages.size(), "volatile hole fixture");
      const std::array<std::pair<uint64_t, uint64_t>, 4> writes = {{{0, 512}, {hole * 4096 + 4091, 8193}, {logical - 512, 512}, {8192 + 17, 63}}};
      for (const auto &write : writes) {
        for (uint64_t j = 0; j < write.second; ++j) ops.buffer[16 + j] = uint8_t(j * 31 + 7);
        std::vector<uint8_t> expected(ops.buffer.begin() + 16, ops.buffer.begin() + 16 + write.second);
        check(ramSparseIO(disk, true, write.first, write.second, ops, oom) == write.second && !oom, "volatile write");
        std::fill(ops.buffer.begin() + 16, ops.buffer.begin() + 16 + write.second, 0);
        check(ramSparseIO(disk, false, write.first, write.second, ops, oom) == write.second && !oom &&
              std::equal(expected.begin(), expected.end(), ops.buffer.begin() + 16), "volatile read-after-write"); ops.guards();
      }
      pass("write-existing-seed-page"); pass("write-unallocated-hole-and-cross-page"); pass("write-last-sector"); pass("unaligned-short-write");
      uint64_t allocated = ops.allocations.size();
      for (const auto &range : std::array<std::pair<uint64_t, uint64_t>, 4>{{{0, 0}, {logical, 1}, {logical - 1, 2}, {UINT64_MAX, 4096}}}) {
        check(!ramSparseIO(disk, true, range.first, range.second, ops, oom) && !oom && ops.allocations.size() == allocated, "invalid range changed storage");
      }
      pass("zero-overrun-and-overflow-ranges");
      ops.transferLimit = 29;
      check(ramSparseIO(disk, false, 0, 512, ops, oom) == 29 && !oom, "short descriptor read is not truthful");
      check(ramSparseIO(disk, true, 0, 512, ops, oom) == 29 && !oom, "short descriptor write is not truthful");
      ops.guards(); pass("truthful-short-descriptor-transfers");
      for (uint64_t budget : {0ULL, 1ULL}) {
        std::vector<uint8_t *> failedPages(logical / 4096); RamSparseDisk failed{failedPages.data(), logical, 0}; Ops failing;
        failing.allocationLimit = budget;
        check(ramSparseIO(failed, true, 0, 8192, failing, oom) == budget * 4096 && oom && failed.resident == budget * 4096,
              "allocation failure completion differs"); failing.guards();
      }
      pass("zero-allocation-failure"); pass("partial-allocation-failure");
      // The imported seed and the encoded input are independent from writable pages.
      check(!memcmp(seed.find(0), input.data() + 32 + 16 * extents, 4096), "volatile writes changed original seed");
      pass("writes-preserve-immutable-seed");
    }
    const char *names[] = {"truncated-header", "bad-magic", "bad-version", "bad-page-size", "zero-logical-size", "oversize-logical-size",
                           "misaligned-logical-size", "excessive-count", "zero-extent", "extent-offset-overflow", "misaligned-extent", "trailing-data"};
    for (unsigned i = 0; i < std::size(names); ++i) {
      auto broken = input;
      switch (i) {
        case 0: broken.resize(31); break;
        case 1: broken[0] ^= 1; break;
        case 2: broken[8] ^= 1; break;
        case 3: broken[12] ^= 1; break;
        case 4: put64(broken, 16, 0); break;
        case 5: put64(broken, 16, (1ULL << 40) + 4096); break;
        case 6: put64(broken, 16, logical + 1); break;
        case 7: put64(broken, 24, 65537); break;
        case 8: put64(broken, 40, 0); break;
        case 9: put64(broken, 32, UINT64_MAX - 4095); break;
        case 10: put64(broken, 32, 1); break;
        case 11: broken.push_back(0); break;
      }
      uint64_t ignored = 0;
      check(!ramPackedLayout(broken.data(), broken.size(), &ignored) && !seedCountNonzero(broken.data(), broken.size(), &ignored), names[i]); pass(names[i]);
    }
    auto invalid = input; put64(invalid, 40, 0);
    Ops rejected; std::vector<uint8_t *> rejectedPages(logical / 4096); RamSparseDisk rejectedDisk{rejectedPages.data(), logical, 0};
    check(!ramSparseImport(rejectedDisk, invalid.data(), invalid.size(), rejected) && rejected.allocations.empty(), "invalid import allocated pages");
    pass("malformed-import-has-no-allocation");
    Digest unchanged; Digest::init(unchanged); Digest::update(unchanged, input.data(), input.size()); Digest::final(unchanged, identity.data());
    std::printf("{\"result\":\"PASS\",\"logical_bytes\":%llu,\"nonzero_pages\":%llu,\"resident_seed_bytes\":%llu,\"encoded_input_sha256\":\"%s\",\"case_count\":%zu,\"cases\":[",
                static_cast<unsigned long long>(logical), static_cast<unsigned long long>(nonzero), static_cast<unsigned long long>(seed.resident), hex(identity.data()).c_str(), cases.size());
    for (size_t i = 0; i < cases.size(); ++i) std::printf("%s\"%s\"", i ? "," : "", cases[i].c_str());
    std::puts("]}"); return 0;
  } catch (const std::exception &error) { std::fprintf(stderr, "%s\n", error.what()); return 1; }
}
