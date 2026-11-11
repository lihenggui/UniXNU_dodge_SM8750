/* SPDX-License-Identifier: MIT */
#include "DodgeNativeA830Board.h"
#include "NativeAdrenoFirmware.h"
#include "NativeAdrenoSha256.h"
#include "A830Votes.h"
#include "A830GmuFirmware.h"
#include "A830Zap.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <thread>
#include <vector>

/* The entry uses firmware symbol peers here; the local firmware run below checks
 * every real file with the production SHA, GMU and ZAP parsers. */
extern "C" {
extern const uint8_t sm8750_gpu_gmu[] = {0}, sm8750_gpu_sqe[] = {0}, sm8750_gpu_aqe[] = {0}, sm8750_gpu_zap[] = {0};
extern const uint64_t sm8750_gpu_gmu_size = 88896, sm8750_gpu_sqe_size = 111476,
    sm8750_gpu_aqe_size = 25044, sm8750_gpu_zap_size = 12088;
}
#include "../drivers/DodgeGpu/DodgeNativeA830Start.cpp"

static unsigned checks;
#define CHECK(x) do {if (!(x)) {std::fprintf(stderr, "line %d: %s\n", __LINE__, #x); std::abort();} ++checks;} while (0)
static std::atomic<unsigned> starts;
static std::atomic<bool> wrongStart;
static std::map<std::string, uint32_t> arguments;
static unsigned requests;

static bool get(void *, const char *key, uint32_t *value)
{
    if (std::strncmp(key, "dodge-", 6)) std::abort();
    ++requests;
    auto it = arguments.find(key);
    if (it == arguments.end()) return false;
    *value = it->second;
    return true;
}
bool PE_parse_boot_argn(const char *key, void *value, int bytes)
{
    if (bytes != sizeof(uint32_t)) std::abort();
    return get(nullptr, key, static_cast<uint32_t *>(value));
}
extern "C" IOReturn adreno830_start(const Adreno830Board *b)
{
    if (b->magic != Adreno830BoardMagic || b->soc_id != 618 || b->sqe_fw.length != 111476 ||
        b->knobs.actlr != 0x32b || b->tsens_tm.phys != 0xc22a000) wrongStart = true;
    ++starts;
    return kIOReturnIOError;
}

static void firmwareTests(const char *directory)
{
    for (unsigned i = 0; i < 4; ++i) {
        const auto *pin = NativeAdrenoFirmware::pin(i);
        std::vector<uint8_t> bytes;
        if (directory) {
            std::ifstream file(std::string(directory) + "/" + pin->name, std::ios::binary);
            CHECK(file.good());
            bytes.assign(std::istreambuf_iterator<char>(file), {});
            CHECK(bytes.size() == pin->bytes);
        } else {
            bytes.resize(pin->bytes, uint8_t(i + 1));
        }
        NativeAdrenoFirmwareView view = {};
        CHECK(NativeAdrenoFirmware::validatePinned(i, bytes.data(), bytes.size(), &view) ==
              (directory ? kIOReturnSuccess : kIOReturnIOError));
        if (directory) {
            CHECK(view.bytes == bytes.data() && view.length == bytes.size());
            if (i == 0) {
                A830GmuBlocks blocks = {};
                CHECK(A830GmuFirmware::parse(bytes.data(), bytes.size(), &blocks) == kIOReturnSuccess);
                CHECK(blocks.metadata == 11 && blocks.data == 4 && blocks.end == bytes.size());
                CHECK(blocks.hfi == 0x20070001);
            } else if (i == 3) {
                A830ZapImage image = {};
                CHECK(A830Zap::parseMdt(bytes.data(), bytes.size(), &image) == kIOReturnSuccess);
                CHECK(image.metadata_bytes == 0xfcc && image.span == 0x1000 && image.loads == 1);
                uint8_t metadata[4096]; size_t size = 0;
                CHECK(A830Zap::buildMetadata(image, metadata, sizeof metadata, &size) == kIOReturnSuccess);
                CHECK(size == 0xfcc);
            }
        } else CHECK(view.bytes == nullptr && view.length == 0);
        bytes[bytes.size() / 2] ^= 1;
        CHECK(NativeAdrenoFirmware::validatePinned(i, bytes.data(), bytes.size(), &view) == kIOReturnIOError);
        CHECK(view.bytes == nullptr && view.length == 0);
        CHECK(NativeAdrenoFirmware::validatePinned(i, bytes.data(), bytes.size() - 1, &view) == kIOReturnBadArgument);
    }
    NativeAdrenoFirmwareView view = {};
    CHECK(NativeAdrenoFirmware::pin(4) == nullptr);
    CHECK(NativeAdrenoFirmware::validatePinned(4, nullptr, 0, &view) == kIOReturnBadArgument);
}

int main(int argc, char **argv)
{
    CHECK(argc <= 2);
    Adreno830Firmware fw[4] = {};
    const uint8_t dummy = 0;
    for (unsigned i = 0; i < 4; ++i) {
        const auto *pin = NativeAdrenoFirmware::pin(i);
        fw[i].bytes = &dummy; fw[i].length = pin->bytes;
        std::memcpy(fw[i].sha256, pin->sha256, 32);
    }
    Adreno830Board b = {};
    CHECK(DodgeNativeA830FillBoard(nullptr, 618, fw) == kIOReturnBadArgument);
    CHECK(DodgeNativeA830FillBoard(&b, 0, fw) == kIOReturnUnsupported && b.magic == 0);
    CHECK(DodgeNativeA830FillBoard(&b, 639, fw) == kIOReturnSuccess && b.soc_id == 639);
    CHECK(DodgeNativeA830FillBoard(&b, 618, fw) == kIOReturnSuccess && b.soc_id == 618);
    CHECK(b.gpu.phys == 0x3d00000 && b.gpu.bytes == 0x40000);
    CHECK(b.zap.phys == 0x9b09a000 && b.zap.bytes == 0x2000);
    CHECK(b.tsens_tm.phys == 0xc22a000 && b.tsens_tm.bytes == 0x1ff);
    CHECK(b.llcc[4].phys == 0x26800000 && b.llcc[5].phys == 0x26c00000);
    CHECK(b.irq_gpu == 332 && b.irq_hfi == 336 && b.irq_gmu == 337 && b.irq_cx_host == 112);
    CHECK(b.irq_smmu_global == 706 && b.irq_smmu_cb[0] == 710 && b.irq_smmu_cb[3] == 713 && b.irq_scm_waitq == 994);
    CHECK(b.sid_gpu == 0 && b.sid_lpac == 1 && b.sid_gmu == 5 && b.cb_gpu == 0 && b.cb_gmu == 2);
    CHECK(b.speedbin_bits == 9 && b.qfprom_speedbin_offset == 0x138 && b.smmu_actlr == 0x32b);
    CHECK(b.ddr_levels == 12 && b.ddr_kbps[11] == 18597656 && b.common_level_count == 11);
    CHECK(b.knobs.actlr == 0x32b && b.knobs.ddr_boot == b.knobs.ddr_floor && b.flags == 0);
    CHECK(b.sqe_fw.length == 111476 && b.aqe_fw.length == 25044 && b.zap_fw.sha256[0] == 0xc1);
    for (unsigned i = 0; i < 4; ++i) {
        auto saved = fw[i];
        fw[i].sha256[0] ^= 1;
        CHECK(DodgeNativeA830FillBoard(&b, 618, fw) == kIOReturnBadArgument && b.magic == 0);
        fw[i] = saved; --fw[i].length;
        CHECK(DodgeNativeA830FillBoard(&b, 618, fw) == kIOReturnBadArgument && b.magic == 0);
        fw[i] = saved; fw[i].bytes = nullptr;
        CHECK(DodgeNativeA830FillBoard(&b, 618, fw) == kIOReturnBadArgument && b.magic == 0);
        fw[i] = saved;
    }
    CHECK(DodgeNativeA830FillBoard(&b, 618, fw) == kIOReturnSuccess);
    const uint32_t speed[] = {190, 221, 232, 0, 242, 0}, sku[] = {9, 9, 9, 1, 9, 3};
    const uint32_t top[] = {900000, 1050000, 1100000, 1100000, 1150000, 1200000};
    const uint8_t count[] = {11, 13, 14, 14, 14, 15};
    for (unsigned i = 0; i < 6; ++i) {
        A830VoteTables votes = {};
        CHECK(A830Votes::selectLevels(b, {speed[i], sku[i], 0, 0}, &votes) == kIOReturnSuccess);
        CHECK(votes.levels == 11 && votes.level[10].khz == 900000 && votes.initial == 2);
        CHECK(A830Votes::selectLevels(b, {speed[i], sku[i], 1, 0}, &votes) == kIOReturnSuccess);
        CHECK(votes.bin == int(i) && votes.levels == count[i] && votes.level[votes.levels - 1].khz == top[i]);
        CHECK(votes.level[0].khz == 160000 && votes.level[3].acd == 0xc8285ffd);
        for (unsigned k = 1; k < votes.levels; ++k) CHECK(votes.level[k].khz > votes.level[k - 1].khz);
    }
    ++b.common_level_count;
    A830VoteTables votes = {};
    CHECK(A830Votes::selectLevels(b, {190, 9, 0, 0}, &votes) == kIOReturnBadArgument);
    --b.common_level_count;
    arguments = {{"dodge-gpu-ddr", 6}, {"dodge-gpu-pool", 256}, {"dodge-gpu-actlr", 0x303},
                 {"dodge-screenoff", 2}, {"dodge-diag", 1}};
    requests = 0;
    DodgeNativeA830ParseKnobs(&b, get, nullptr);
    CHECK(requests == Adreno830KnobCount + 2);
    CHECK(b.knobs.ddr_boot == 6 && b.knobs.ddr_floor == 6 && b.pool_mib == 256);
    CHECK(b.knobs.actlr == 0x303 && b.knobs.screenoff == 2 && b.system_diag == 1);
    CHECK(b.flags & Adreno830BoardFlagPool);
    arguments.clear(); requests = 0;
    attempted = 0;
    CHECK(dodge_native_a830_start(999) == kIOReturnUnsupported && starts == 0);
    CHECK(dodge_native_a830_start(618) == kIOReturnBusy && starts == 0);
    attempted = 0;
    arguments = {{"dodge-gpu-async", 1}};
    CHECK(dodge_native_a830_start(618) == kIOReturnUnsupported && starts == 0);
    attempted = 0; arguments.clear();
    std::atomic<bool> go{false};
    std::atomic<unsigned> busy{0}, failed{0};
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 16; ++i) threads.emplace_back([&] {
        while (!go.load()) std::this_thread::yield();
        IOReturn r = dodge_native_a830_start(618);
        if (r == kIOReturnBusy) ++busy;
        if (r == kIOReturnIOError) ++failed;
    });
    go = true;
    for (auto &thread : threads) thread.join();
    CHECK(starts == 1 && busy == 15 && failed == 1 && !wrongStart);
    CHECK(dodge_native_a830_start(618) == kIOReturnBusy && starts == 1);
    firmwareTests(argc == 2 ? argv[1] : nullptr);
    std::printf("PASS: %u CPH2653 board checks; six real level selections; 16-way entry; firmware %s\n",
                checks, argc == 2 ? "stock files verified" : "metadata and refusal controls");
}
