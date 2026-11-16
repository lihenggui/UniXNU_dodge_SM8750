// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <assert.h>
#include <string>
#include <vector>
#include "../drivers/DodgeStorage/DodgeSeedSync.cpp"
#include "SeedClose.inc"

static SeedTestMount dataMount, otherMount;
static SeedTestNode seed, data, directory;
static vnode_attr attributes;
static DodgeDataMountStatus mounted;
static bool enabled, ready;
static std::string fault;
static int closeError, closeCalls, namePins;
static std::vector<std::string> events;
int vnode_vtype(vnode_t node) { return node->type; }
mount_t vnode_mount(vnode_t node) { return node->mount; }
bool vnode_isvroot(vnode_t node) { return node->root; }
unsigned vfs_flags(mount_t mount) { return mount->flags; }
vfsstatfs *vfs_statfs(mount_t mount) { return fault == "statfs" ? nullptr : reinterpret_cast<vfsstatfs *>(mount); }
int vnode_lookup(const char *path, unsigned flags, vnode_t *out, vfs_context_t) {
    assert(!flags);const bool db = !strcmp(path, "/private/var/db");
    assert(db || !strcmp(path, "/private/var"));
    events.emplace_back(db ? "directory" : "Data");
    if (fault == (db ? "directory" : "Data")) return EIO;
    *out = db ? &directory : &data; ++(*out)->references;return 0;
}
int vnode_getattr(vnode_t node, vnode_attr *out, vfs_context_t) {
    assert(node == &seed && out->va_active == 31); events.emplace_back("attributes");
    if (fault == "attributes") return EIO;
    *out = attributes;return 0;
}
int vnode_getwithref(vnode_t node) {
    assert(node == &seed);
    if (fault == "getref") return EIO;
    ++node->references;return 0;
}
int vnode_put(vnode_t node) { assert(node->references);--node->references;return 0; }
const char *vnode_getname(vnode_t node) { ++namePins;return node->name; }
void vnode_putname(const char *) { assert(namePins);--namePins; }
int vn_getpath(vnode_t node, char *out, int *bytes) {
    if (fault == "path") return ENOENT;
    assert(size_t(*bytes) > strlen(node->path));strcpy(out, node->path);*bytes = int(strlen(out) + 1);return 0;
}
bool PE_parse_boot_argn(const char *name, void *out, int bytes) {
    assert(!strcmp(name, "dodge-seed-sync") && bytes == 4);*static_cast<unsigned *>(out) = unsigned(enabled);return enabled;
}
extern "C" bool dodge_owner_security_ready() { return ready; }
extern "C" void dodge_data_mount_status(DodgeDataMountStatus *out) { *out = mounted; }
int VNOP_FSYNC(vnode_t node, int wait, vfs_context_t) {
    assert(wait == MNT_WAIT && (node == &seed || node == &directory));
    std::string step = node == &seed ? "seed-sync" : "directory-sync";
    events.push_back(step);return fault == step ? EIO : 0;
}
int VNOP_IOCTL(vnode_t node, unsigned long op, void *value, int flags, vfs_context_t) {
    assert(node == &seed && op == F_FULLFSYNC && !value && !flags);events.emplace_back("full-sync");
    return fault == "full-sync" ? EIO : fault == "unsupported-full-sync" ? ENOTSUP : 0;
}
int vn_close(vnode_t node, int, vfs_context_t) { assert(node == &seed);++closeCalls;events.emplace_back("close");return closeError; }
int VNOP_ADVLOCK(vnode_t node, char *, int op, struct flock *lock, int, vfs_context_t, void *) {
    assert(node == &seed && op == F_UNLCK && lock->l_type == F_UNLCK);events.emplace_back("unlock");return 0;
}
static void reset() {
    dataMount = {{'a','p','f','s',0}, 0}; otherMount = dataMount;
    seed = {VREG, &dataMount, false, 1, "prng.seed", "/private/var/db/prng.seed"};
    data = {VDIR, &dataMount, true, 0, "var", "/private/var"};
    directory = {VDIR, &dataMount, false, 0, "db", "/private/var/db"};
    attributes = {0, 31, 1, 32, 0, 0, 0600};
    mounted = {DodgeDataMountPhase::Mounted, 0, true, true, true};
    enabled = ready = true;fault.clear();events.clear();closeCalls = namePins = closeError = 0;
    dodge_seed_sync_attempts = dodge_seed_sync_completed = dodge_seed_sync_failed = 0;dodge_seed_sync_last_error = 0;
}
static unsigned cases;
static void check(int wanted, bool synchronized, int flags = FWRITE, int locks = 0) {
    fileglob file{&seed, flags, locks};
    assert(vn_closefile(&file, nullptr) == wanted);
    assert(seed.references == 1 && !directory.references && !data.references && !namePins);
    assert(closeCalls == (fault != "getref"));
    assert(dodge_seed_sync_completed == unsigned(synchronized));
    if (synchronized) {
        assert(events == (std::vector<std::string>{"Data", "attributes", "directory", "seed-sync", "directory-sync", "full-sync", "close"}));
    }
    ++cases;
}
int main() {
    reset();check(0, true);
    reset();seed.path = "/var/db/prng.seed";check(0, true);
    for (const char *step : {"getref", "Data", "attributes", "directory", "seed-sync", "directory-sync", "full-sync"}) {
        reset();fault = step;check(EIO, false);
        if (fault != "getref") assert(closeCalls == 1);
    }
    reset();fault = "path";check(ENOENT, false);
    reset();fault = "statfs";check(EROFS, false);
    reset();fault = "unsupported-full-sync";check(ENOTSUP, false);
    for (unsigned bit = 0; bit < 5; ++bit) { reset();attributes.va_supported &= ~(UINT64_C(1) << bit);check(ENOTSUP, false); }
    for (uint64_t bytes : {UINT64_C(0), UINT64_C(1), UINT64_C(31), UINT64_C(33), UINT64_MAX}) {
        reset();attributes.va_data_size = bytes;check(EAUTH, false);
    }
    for (unsigned mode : {0U, 0400U, 0640U, 0644U, 0666U, 04600U}) { reset();attributes.va_mode = mode;check(EAUTH, false); }
    reset();attributes.va_uid = 501;check(EAUTH, false);
    reset();attributes.va_gid = 20;check(EAUTH, false);
    reset();attributes.va_nlink = 2;check(EAUTH, false);
    reset();dataMount.flags = MNT_RDONLY;check(EROFS, false);
    reset();strcpy(dataMount.type, "hfs");check(EROFS, false);
    reset();data.root = false;check(EAUTH, false);
    reset();directory.type = VREG;check(EAUTH, false);
    reset();directory.mount = &otherMount;check(EAUTH, false);
    reset();seed.mount = &otherMount;check(EAUTH, false);
    reset();mounted.resultVerified = false;check(EAGAIN, false);
    reset();mounted.phase = DodgeDataMountPhase::Preparing;check(EAGAIN, false);
    reset();closeError = ENXIO;check(ENXIO, true);
    reset();closeError = ENXIO;fault = "full-sync";check(ENXIO, false);
    reset();ready = false;check(0, false);assert(events.size() == 1 && !dodge_seed_sync_attempts);
    reset();enabled = false;check(0, false);assert(events.size() == 1 && !dodge_seed_sync_attempts);
    reset();seed.type = VDIR;check(0, false);assert(events.size() == 1 && !dodge_seed_sync_attempts);
    reset();seed.name = "other";check(0, false);assert(events.size() == 1 && !dodge_seed_sync_attempts);
    reset();seed.path = "/other/prng.seed";check(0, false);assert(events.size() == 1 && !dodge_seed_sync_attempts);
    reset();check(0, false, FREAD);assert(events.size() == 1 && !dodge_seed_sync_attempts);
    reset();check(0, false, FREAD | FWASLOCKED, FG_HAS_OFDLOCK);assert(events == (std::vector<std::string>{"unlock", "unlock", "close"}));
    reset();fault = "full-sync";check(EIO, false);
    const unsigned values[] = {1, 0, 1, EIO};
    for (unsigned i = 0; i < 4; ++i) {
        sysctl_req request{};assert(!dodge_seed_sync_sysctl(nullptr, nullptr, int(i), &request));
        assert(request.bytes == 4 && request.value == values[i]);++cases;
    }
    sysctl_req request{};request.result = EFAULT;assert(dodge_seed_sync_sysctl(nullptr, nullptr, 0, &request) == EFAULT);++cases;
    request = {};request.newptr = 1;assert(dodge_seed_sync_sysctl(nullptr, nullptr, 0, &request) == EPERM);++cases;
    request = {};assert(dodge_seed_sync_sysctl(nullptr, nullptr, 4, &request) == EINVAL);++cases;
    assert(test_oid_dodge_seed_sync_failed.flags == (CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED));
    printf("PASS: %u original close and seed sync ordering, refusal, failure and ownership cases\n", cases);
}
