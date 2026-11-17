# Build guide

Commands below run from the repository root. They prepare sources, build local
files and run host tests. A connected phone is not required.

## Target

| Setting | Value |
| --- | --- |
| Board | OnePlus 13 CPH2653, dodge, SM8750 |
| Firmware input | CPH2653_16.0.1.304(EX01) |
| iPhone system | iPhone10,3 / D22AP / iOS 16.7.16 / 20H392 |
| Chip and board ID | 0x8015 / 6 |
| Original kernel | arm64, Darwin 22.6.0, XNU 8796.142.1.703.8 |
| Public XNU source | xnu-8796.141.3, commit `1b191cb58250d0705d8a51287127505aa4bc0789` |

[targets/iphone-x-ios16.toml](../targets/iphone-x-ios16.toml) contains the Apple
download URL, BuildManifest identity and hashes.
[upstream.lock.json](../upstream.lock.json) pins source revisions and patches.

The [official guide](https://unixnu.com/porting/) was reviewed on 2026-11-12
against [UniXNU `dff2765`](https://github.com/UniXNU/UniXNU/tree/dff276535db3ac394f628cec58a718cd46c20ac2). Follow its order:
resolve the board and OS profile, verify memory and firmware, build platform
services, then add storage, display, input and GPU support. Keep host results
and device observations separate in [porting.toml](../porting.toml).

Mainline now includes `firmware_tools` for Data-addon firmware staging and a
Metal pipeline compilation policy that uses the calling thread when its stack
has at least 2 MiB. The native route backports that policy and keeps the existing
thread relay for smaller stacks. Its latest Turnip change keeps the Vulkan
device after a GPU restart. The native route applies that behavior with
per-surface failure tracking, because this backend abandons in-flight jobs
during recovery. Source revisions remain pinned in the lock file; this board
embeds its four stock GPU microcode files locally.

The native route also backports shader sharing across pipeline caches and
buffer-cache lookup before retired-buffer collection. Its Metal frontend forwards
tile pipeline creation, resources, pass memory and dispatch to the pinned runtime.
Tile dimensions follow the pass's attachments and the runtime's 32x16 default
at four samples. The existing device-family and tile-capability answers are retained.

The 13T review covers [Shad0w23333 `25b1109`](https://github.com/Shad0w23333/UniXNU-Pagani_SM8750/tree/25b110978fec628cc29bf5bd1b5b5ce830156bfd)
and [IssacL04 `a84204e`](https://github.com/IssacL04/UniXNU-Pagani_SM8750/tree/a84204eccb9b183945072e1b9b63de36c8495097).
The native A830 driver remains at its latest `1a132105` revision. This board's
memory reservations, touch rails, panel, GPU levels and firmware come from the
CPH2653 capture. Peripheral work in the newer 13T integration also needs those
board inputs and iPhone-specific interfaces.

## Upstream review

The 2026-11-14 review checks 32 repositories and 33 branch references against
the selected sources. [The snapshot](../reports/public/upstream-review.json)
records the remote revisions, commit relationships, input hashes and adaptation
decisions. This review retains all source pins and the firmware memory patch.

At that review UniXNU main was [`0c1bac3`](https://github.com/UniXNU/UniXNU/tree/0c1bac3d51a3009dca1708b15a5198f4b43d057a),
16 commits beyond the previous `dff2765` review. That range changes host IPSW
downloads, log presentation, macOS VM/account handling and device documentation.
It does not change component gitlinks or the component catalog. The new VM
patches belong to the macOS `xnu-12377` profile and need an independent Darwin 22
port if selected for this target.

| Source | Observed tip | Effect on this port |
| --- | --- | --- |
| Native Adreno 830 | `1a132105` | Current pin is still the driver tip. Both reviewed 13T reference tips are also unchanged. |
| ArmCpu / ArmDTPlatform | `d90e457b` / `e8bd8d5d` | Calendar/clock registration and missing-RTC handling are backported to Darwin 22 in the separate native system build. Shared interrupts, idle/IPI ownership and a real board RTC still need work. |
| DarwinBoot | `5243c68e` | Excluded/outside memory ranges and loader input records require matching kernel consumers and owner-manifest handling. |
| ArmSmmu4K | `83969cd8` | Switched TTBR0 handling, demand page tables and live traversal change the API used by the pinned A830 fixed-pool integration. |
| RamBlock | `00a6e5dd` | Concurrent/cached I/O and seed-memory release need the measured iPhone class, flush/durability and memory-lifetime checks. |
| XnuPrelink | `440589b0` | The new work concerns filesets and newer OS fixtures; retain the passing legacy iPhone closure and its measured bindings. |
| Mainline Adreno740 / AdrenoMetal | `54b41b8f` / `73d582fd` | Retain the existing A830 backports; review further fault isolation, memory and presentation changes against this backend and iPhone clients. |
| Mesa / metal2vulkan development | `c9ce420e` / `400efe79` | New references exist; a complete Mesa or translator rebase and its API compatibility were not performed in this review. |

Three Issac GPU reference defaults are one commit behind their selected pins.
metal2vulkan's default and development branches diverge from the selected
revision. These relationships require checking the intended source branch
before choosing a change. The larger Mesa/translator histories are outside the
targeted difference review. QcomGeniSpi, VirtIO block, VerifiedRoot, SoftwareAES,
KeyStore, AdrenoPM4 and AirNir retain their observed component revisions.

The newer SM8750/Pagani references also contain peripheral integration, and
mainline includes QcomBaseband. Their network, audio and USB work still requires
CPH2653 power/resource/firmware inputs and original iPhone interfaces. None of
those reference-board results establishes this board's functionality.

The [2026-11-16 follow-up](../reports/public/upstream-continuation-2026-11-16.json)
rechecks eight selected references. UniXNU main is
[`4a654d1`](https://github.com/UniXNU/UniXNU/tree/4a654d1f31662f18ab94391a4f0297b17b9bb2fe),
85 commits and 301 changed files beyond `0c1bac3`. That range changes macOS
workflows and toolchains, graphics/CPU/RamBlock selections, texture policy and
Bluetooth discovery tracing. It has not been fully rebased or audited line by
line for Darwin 22. The native A830, ArmSmmu4K, SM8750 common and reviewed 13T
tips remain unchanged. Ath12kWifi now integrates the Linux wireless runtime and
supplicant; QcomBaseband exposes carrier/PDP/CommCenter work for its reference
board and newer OS. Those references still need CPH2653 resources and original
iPhone interfaces. This scoped follow-up supplements the earlier 32-repository
review; it does not refresh every earlier reference.

The [HID follow-up](../reports/public/upstream-hid-lifecycle-review.json)
rechecks four references: UniXNU, Pagani drivers, GopFramebuffer and QcomGeniSpi.
At observation, UniXNU main is
[`b6ac063`](https://github.com/UniXNU/UniXNU/tree/b6ac0630ed55feb926ccf2961523fca08bf2464e),
89 commits and 144 changed files beyond `4a654d1`. Selected build changes
propagate OS-profile/toolchain inputs and preserve cached source timestamps
with preparation rollback. The local native route already uses recorded
Darwin 22 recipes and isolated exact overlays. The range also changes Metal
runtime selection and graphics inspection/telemetry; that full history has not
been audited or rebased for this iPhone target. The other three observed tips
are unchanged. Existing pins and the memory patch remain in place; the earlier
32-repository and eight-reference reviews remain separate snapshots.

## Host setup

The existing builds used Ubuntu 22.04 / WSL and Python 3.12. CI runs on
Ubuntu 24.04. Scripts use four jobs and inherit host resource limits. The
20 GiB limit recorded in older reports describes that build machine.

Install system packages:

```sh
sudo apt-get install build-essential clang-14 lld-14 llvm-14 llvm-14-dev \
  libclang-14-dev uuid-dev libbsd-dev libssl-dev zlib1g-dev liblzma-dev \
  nasm mono-devel ca-certificates-mono device-tree-compiler mtools cmake \
  ninja-build unifdef pkg-config flex bison cpio rsync tcsh patch ruby \
  qemu-system-arm qemu-efi-aarch64 seabios
```

Set up Python and restore the sources:

```sh
python3.12 -m venv .venv-uefi
.venv-uefi/bin/python -m pip install -r requirements-host.lock
.venv-uefi/bin/python scripts/prepare_sources.py --apply
cp local.toml.example local.toml
.venv-uefi/bin/python scripts/build_host_tools.py --check-iig
./unixnu defconfig dodge_defconfig
./unixnu fetch
```

`prepare_sources.py` checks existing checkouts by default. With `--apply`, it
fetches pinned revisions and applies their patches. Conflicting local edits
stop the operation.

Build the XNU toolchain:

```sh
sudo env PATH="$PWD/.venv-uefi/bin:$PATH" \
  .venv-uefi/bin/python sources/UniXNU/scripts/linux/setup-toolchain.py \
  "$PWD/.toolchains/xnu-linux" --package-manager none \
  --llvm-config /usr/lib/llvm-14/bin/llvm-config -j 4
```

The installer builds into the local prefix and installs host compatibility
commands for `xcrun`, `plutil` and `codesign`. The `./unixnu` wrapper selects
this toolchain, the local Python environment and four jobs.

## Source checks

```sh
.venv-uefi/bin/python scripts/prepare_sources.py
.venv-uefi/bin/python scripts/check_source_patches.py
.venv-uefi/bin/python scripts/test_ios_profile.py
.venv-uefi/bin/python scripts/test_bootimg.py
.venv-uefi/bin/python scripts/test_source_series.py
.venv-uefi/bin/python scripts/test_image4_boot_policy.py
.venv-uefi/bin/python scripts/check_ios16_patches.py
.venv-uefi/bin/python scripts/check_percpu_iteration.py
```

Check the standard packaging entry point after fetching the sources:

```sh
PATH="$PWD/.venv-uefi/bin:$PATH" scripts/package.sh --check --no-deps --os 16 \
  --out build/unixnu -j 4
```

This resolves the iPhone profile and its 62 patches. The full `release` build
also needs the original-component closure and image inputs described below.

[The CI workflow](../.github/workflows/source-checks.yml) also runs driver tests
with software IOKit and register models. Its GENI tests use synthetic firmware.

## Kernel and iPhone inputs

```sh
.venv-uefi/bin/python scripts/fetch_ios_inputs.py
.venv-uefi/bin/python scripts/inspect_ios_kernelcache.py
.venv-uefi/bin/python scripts/prepare_device_tree.py
./unixnu status --os 16 --json
./unixnu kernel --skip-prelink
.venv-uefi/bin/python scripts/validate_kernel_artifacts.py
```

Apple inputs are cached under `build/unixnu/ipsw/20H392/`. The initial device
tree enables CPU0 and hands over 4 GiB of memory. The generated platform identity
is stored in `.cache/platform.json` with mode 0600.

`--skip-prelink` builds the source kernel. To inspect and prelink original
iPhone components:

```sh
.venv-uefi/bin/python scripts/check_libm_literals.py
.venv-uefi/bin/python scripts/check_ios16_security.py
.venv-uefi/bin/python scripts/audit_ios16_bindings.py --try-prelink
.venv-uefi/bin/python scripts/validate_prelinked_kernel.py
```

The per-CPU iteration patch compares unsigned base offsets before forming a
pointer. On a single-CPU boot, the secondary range starts at a high sentinel
and ends at zero. Comparing those offsets as pointers made the mbuf statistics
path enter that empty range and fault with the current compiler. The host check
uses the actual patched macros in C and C++ at O0 through O3, including empty
ranges, multiple CPUs, nesting, writes, break and continue.

## UEFI and boot container

```sh
.venv-uefi/bin/python scripts/build_uefi.py --with-unixnu-menu
.venv-uefi/bin/python scripts/validate_uefi_artifacts.py
.venv-uefi/bin/python scripts/build_local_payload.py
```

Outputs are written to `build/cph2653-uefi-menu/` and
`build/cph2653-native-bringup/`. The latter contains the kernel, iPhone device
tree and FAT payload in an Android boot container.

The firmware includes a 2 MiB DXE log buffer and the UniXNU QR exporter.
Open **Tools > Advanced Logger** in the menu and receive the log with
[OneSend](https://onesend.01mvp.com). The buffer starts in DXE; SEC still uses
the platform's existing debug output. See the
[firmware log guide](https://unixnu.com/porting/log-capture#firmware-setup).

The board memory patch splits the DXE heap around the captured reserved ranges
while keeping the SEC heap contiguous. The
[before](../reports/public/memory-before.json) and
[after](../reports/public/memory-after.json) reports list those ranges.

Optional stock firmware comparison:

```sh
.venv-uefi/bin/python scripts/fetch_stock_gpu_inputs.py \
  --partition uefi --partition xbl --partition imagefv --output-subdir boot-firmware
.venv-uefi/bin/python scripts/audit_stock_uefi.py
.venv-uefi/bin/python scripts/prepare_stock_uefi_patches.py
.venv-uefi/bin/python scripts/check_simplefb.py
```

## Driver builds

Create the GPU/model-test environment and install its pinned tools:

```sh
.venv-uefi/bin/python -m venv .venv-gpu
.venv-gpu/bin/python -m pip install --require-hashes -r requirements-gpu.lock
.venv-uefi/bin/python scripts/prepare_gpu_tools.py
.venv-uefi/bin/python scripts/build_gpu_shader_tools.py
```

The native route uses Shad0w23333's [Adreno830 driver](https://github.com/Shad0w23333/Adreno830)
and matching SMMU library. Both [OnePlus 13T ports](https://unixnu.com/devices/models/oneplus13t)
provide integration references. Board registers, power bins, firmware and the
`0x32b` ACTLR value come from the CPH2653 capture. Original component addresses
and class layouts come from the pinned iPhone kernelcache.

Prepare the [system and Data inputs](#system-and-data-images) before the shared
source stages. These stages supply storage, input, display and original crypto:

| Order | Command |
| --- | --- |
| 1 | `.venv-uefi/bin/python scripts/build_gpu_stack.py` |
| 2 | `.venv-uefi/bin/python scripts/build_storage_stack.py` |
| 3 | `.venv-uefi/bin/python scripts/build_input_stack.py` |
| 4 | `.venv-uefi/bin/python scripts/build_data_stack.py` |
| 5 | `.venv-uefi/bin/python scripts/build_data_startup_stack.py` |
| 6 | `.venv-uefi/bin/python scripts/build_data_mount_stack.py` |
| 7 | `.venv-gpu/bin/python scripts/check_ramblock_start_kernel.py` |
| 8 | `.venv-uefi/bin/python scripts/prepare_ios16_pmgr.py` |
| 9 | `.venv-gpu/bin/python scripts/check_ios16_pmgr_kernel.py` |
| 10 | `.venv-uefi/bin/python scripts/build_crypto_stack.py` |
| 11 | `.venv-uefi/bin/python scripts/prepare_crypto_execution.py` |
| 12 | `.venv-gpu/bin/python scripts/check_original_crypto_kernel.py` |

Add the shared surface and mapped-resource source adapters:

```sh
.venv-gpu/bin/python scripts/prepare_surface_sync.py
.venv-gpu/bin/python scripts/check_surface_sync_kernel.py
.venv-gpu/bin/python scripts/build_fresh_gpu_source.py
.venv-uefi/bin/python scripts/check_mapped_lease_host.py
.venv-uefi/bin/python scripts/build_mapped_lease_source.py
.venv-uefi/bin/python scripts/build_surface_identity.py
.venv-uefi/bin/python scripts/build_surface_pages.py
.venv-uefi/bin/python scripts/build_surface_acquire.py
.venv-uefi/bin/python scripts/build_boot_entropy.py
.venv-gpu/bin/python scripts/check_boot_entropy_kernel.py
```

This produces the 97-object source baseline used by the native kernel builder.
The earlier `build_fresh_gpu_stack.py`, `build_mapped_lease_stack.py` and surface
stack scripts also package or model their own older candidates. The commands
above prepare the shared source inputs for the native route directly.

Prepare the board's stock GPU files and captured declarations:

```sh
.venv-uefi/bin/python scripts/prepare_gpu_firmware.py
.venv-uefi/bin/python scripts/prepare_native_a830.py
```

The firmware step reads the pinned vendor and vendor_boot inputs.
[hardware/dodge-gpu-firmware.json](../hardware/dodge-gpu-firmware.json) records
their hashes. [hardware/dodge-native-a830.json](../hardware/dodge-native-a830.json)
records the register windows, interrupts, streams, six frequency/ACD bins and
eight temperature sensors. Generated headers and microcode stay under `build/`.

Build the native development candidate:

```sh
.venv-gpu/bin/python scripts/build_native_a830_stack.py
.venv-gpu/bin/python scripts/build_native_a830_stack.py --check-only
```

The builder runs each stage in order with four compiler jobs. It builds the
57-object native GPU archive, links the 111-object source kernel and prelinks
28 original iPhone executable components. It checks 63,889 pointer bindings,
four IOSurface lifecycle hooks and the embedded firmware bytes. Turnip, the
Rust bridge and the Metal plugin use separate native build directories.
`--record-existing` validates completed stages and records them without a rebuild.

The native prelink derives security startup from the original module records.
Sandbox's normal start already calls its policy initializer, so its extra
early hook is omitted. AMFI retains the explicit initializer required by its
empty start slot. Both original wrappers and their pointer slots are read back.

The adapter adds task-authorized surface-ID import as selector 19. Selectors
17/18 retain their known record sizes and return Unsupported; this backend
uses its existing FIFO submission policy. Each job holds all current VM
mappings. Original IOSurface writer grants precede GPU submission, and a
deferred worker signals completion after the fence and cache acquisition.
Cancellation keeps pending callback owners alive. Backing changes invalidate
active work and the display health snapshot.

GetStatus distinguishes a restart in progress from permanent device loss.
Turnip keeps the Vulkan device across a successful restart. Each surface whose
writer was abandoned stays blocked from display until a successful writer to
that same surface retires. Previously captured display epochs stay invalid.
An uncertain original completion retains its callback context and tickets.
The host tests cover 24 native runtime cases, 11 Turnip status calls and 136
display frontend cases, alongside the backend, board and VM suites.

The cache tests run the production Turnip functions with Vulkan and kernel peers:
19 cases cover shared references, device isolation, allocation failures and
opportunistic retirement; eight threads perform 800 lookups. Offline translation
also compiles public tile AIR and validates the resulting SPIR-V. To repeat them:

```sh
.venv-gpu/bin/python scripts/check_native_a830_cache.py
.venv-gpu/bin/python scripts/check_metal_translation.py
```

The board entry reads the SoC ID from SMEM before startup and accepts 618 or
639. An optional `dodge-gpu-soc` value must match that reading. The existing
once-only startup gate and original-family initialization order are retained.

| Output | Location |
| --- | --- |
| Prelinked iPhone kernel | `build/cph2653-native-a830-prelink/kernel.macho` |
| Metal addon and iPhone trust inputs | `build/cph2653-native-a830-addon/` |
| Fresh-entropy and DXE logger firmware | `build/cph2653-native-a830-firmware/` |
| FAT payload and Android v4 container | `build/cph2653-native-a830-bringup/` |

The addon uses the official NGPUADD2 format. Its trust bundle contains the
three local executable hashes and the two unchanged 20H392 iPhone trust-cache
payloads. The actual EFI loader runs in an ARM64 model with these files; their
final memory-map addresses and bytes are read back. The model also checks fresh
seed consumption and the original 18-test crypto POST.

The development payload supplies Image4's boot inputs through an owner boot-set
manifest. SHA-384 binds the kernel, trust cache, addon, packed Data seed and
device tree. A private nonce generated per payload build supplies `BNCH`, and
`mix-n-match-prevention-status = 1` keeps manifest mixing disabled. The manifest
uses the `UniXNU.Dodge.Image4BootSet.v1` domain. It describes the development
files; Apple personalization and hardware security state remain separate.
The loader still obtains fresh kernel entropy on every handoff. Binding checks
normalize that entropy and the loader's memory-map address/size records while keeping
the static device tree covered. Twelve host cases check binding, changed inputs,
nonce rotation and preservation of pre-existing firmware policy.

The development container retains the packed 2 GiB Data seed and boot arguments
`-v serial=0 debug=0x14e cpus=1`. Graphics and Data startup remain opt-in through
the existing `dodge-graphics`, `dodge-data` and `dodge-data-mount` arguments.
It contains no original userspace or root image. Hardware power, cache/DMA
visibility, Metal discovery, rendering and full iOS boot still need device
validation. [porting.toml](../porting.toml) tracks those steps.

The archive-only commands remain available for driver work:

```sh
.venv-uefi/bin/python scripts/build_native_a830.py
.venv-uefi/bin/python scripts/build_native_a830.py --board --link
python3 scripts/check_native_a830_host.py
python3 scripts/check_native_a830_host.py --runtime
```

## QEMU entry

The native stack ends with the [official QEMU entry procedure](https://unixnu.com/reference/qemu).
To repeat just that stage after building the payload:

```sh
.venv-gpu/bin/python scripts/check_native_a830_entry.py
.venv-gpu/bin/python scripts/check_native_a830_entry.py --check-only
```

The runner uses AAVMF, the built UniXNU application and entropy loader, and the
kernel read back from the packaged FAT. It preserves iPhone10,3 identity and
substitutes QEMU RAM, CPU and GICv3 resources in a separate device tree. Its
1 GiB owned window and 2 GiB VM RAM apply only to this fixture. Use `--qemu`,
`--firmware`, `--firmware-vars` and `--rom-dir` for other installation paths.

The current kernel reaches `arm_init`, `kernel_bootstrap`, `InitIOKit` and
`bsd_init` at EL1 with the MMU enabled and 4 KiB translation tables. The runner
reads the live MAC policy list using a layout compiled from Darwin 22 headers:
AppleImage4, AMFI and Sandbox are each registered once. The next stop is
`Failed to mount root device`, because this fixture has no root block device.

The virtual device tree receives its own manifest after resource substitution.
Three negative runs omit the mixing policy, `BNCH` or the previous-stage
manifest hash; original Image4 refuses each input. A fourth run omits the
entropy reservation and is refused before ExitBootServices.
Logs are under `build/cph2653-native-a830-entry/`, and the
published result is [native-a830-entry.json](../reports/public/native-a830-entry.json).

This run exercises early kernel startup under TCG. OnePlus firmware, board
drivers and iOS userspace have separate bring-up work in `porting.toml`.

To continue into storage, prepare the system inputs below and build the
separate VirtIO candidate:

```sh
.venv-uefi/bin/python scripts/build_qemu_storage.py
.venv-gpu/bin/python scripts/check_qemu_storage.py
.venv-gpu/bin/python scripts/check_qemu_storage.py --check-only
```

This adds the pinned read-only `VirtioMmioBlock` transport with the measured
iPhone storage interface. Startup waits for platform registration before
collecting the published devices, then loads original IOStorageFamily and APFS.
QEMU attaches the local OS and SystemOS files read-only. Both first-sector DMA
reads match those files, and original APFS mounts the selected root. XNU then
stops at `rootvp not authenticated after mounting`; root authentication remains
the next step. Runs with the startup argument absent or a writable backend
perform no disk reads.
The coordinator also passes 27 sanitizer cases with registry, clock and loader
peers, including delayed registration and an iterator invalidated by startup.

The candidate stays in `build/cph2653-qemu-storage/kernel.macho` and its logs in
`build/cph2653-qemu-storage-entry/`. It preserves the existing packaged payload.
See [the storage result](../reports/public/ios16-qemu-storage-entry.json).

The owner-root fixture adds signed block policies to that transport:

```sh
.venv-uefi/bin/python scripts/prepare_qemu_root_policy.py
.venv-uefi/bin/python scripts/build_qemu_owner_root.py
for fault in signature dma uuid; do
  .venv-uefi/bin/python scripts/build_qemu_owner_root.py --fault "$fault"
done
.venv-gpu/bin/python scripts/check_qemu_owner_root.py
.venv-gpu/bin/python scripts/check_qemu_owner_root.py --check-only
```

Preparation verifies all 2,045,449 original OS/SystemOS blocks with the C
implementation. In QEMU, the original iPhone RSA callbacks verify both policies,
and the transport checks each completed read before exposing it. The independent
owner policy requires the mounted root to be read-only and match the signed
volume UUID and selected device. The original Apple ioctl still returns `EAUTH`.
With owner authorization, the kernel reaches `load_init_program`; this fixture
stops before user instructions execute. Damaged signatures, changed DMA buffers
and a valid signature for the wrong UUID are refused.

The local RSA3072 key stays under `.cache/qemu-root-owner/`. Policies and kernels
stay under `build/`. Generation 1 is the minimum for this development fixture;
persistent rollback protection and hardware trust have separate implementation
work. The [owner-root result](../reports/public/ios16-qemu-owner-root-entry.json)
records the original callback addresses, mounted-device checks and controls.
CI runs the nine C/signature test groups with `--host-only` and no iPhone files.

To run the original init executable, add its filesystem decompressor:

```sh
.venv-uefi/bin/python scripts/build_qemu_exec.py
.venv-gpu/bin/python scripts/check_qemu_exec.py
.venv-gpu/bin/python scripts/check_qemu_exec.py --check-only
```

This candidate adds `AppleFSCompressionTypeZlib` from the same iPhone kernelcache.
All 64,635 pointer bindings and the original component instructions are checked.
QEMU reaches PID 1, named `launchd`, with the original executable UUID. Its first
EL0 instruction belongs to the original `/usr/lib/dyld`; 64 entry bytes match
read-only extraction from the OS image. The check single-steps that instruction
and stops. Without the decompressor, exec returns `ENOTSUP` before EL0.
The [exec result](../reports/public/ios16-qemu-exec-entry.json) records both runs.
Add SoftwareAES to let the original Image4 service finish startup:

```sh
.venv-uefi/bin/python scripts/build_qemu_aes.py
.venv-uefi/bin/python scripts/build_qemu_aes.py --negative-kat
.venv-gpu/bin/python scripts/check_qemu_aes.py
.venv-gpu/bin/python scripts/check_qemu_aes.py --check-only
```

The build derives the 288-byte AES class, all 181 dispatch slots and its original
bindings from the iPhone kernelcache. The provider passes its CBC and memory
descriptor self-tests. QEMU uses a separate identifier derived from the owner's
public anchor for the software nonce key. This is a public development identity;
Apple personalization and hardware keys have separate implementations.

Original dyld returns from `security.mac.img4.ignition_blob`, enters `prepare`
and calls the shared-cache loader. It then reports a missing
`/usr/lib/libSystem.B.dylib` and no dyld cache. SystemOS contains the prepared
cache and still needs attachment at its iPhone path. A wrong CBC answer prevents
provider registration; an absent VM identifier produces the original unsupported
key panic. See [the AES result](../reports/public/ios16-qemu-aes-entry.json).

Mount SystemOS through the existing Darwin 22 owner union path:

```sh
.venv-uefi/bin/python scripts/build_qemu_systemos.py
.venv-uefi/bin/python scripts/build_qemu_systemos.py --wrong-uuid
.venv-gpu/bin/python scripts/check_qemu_systemos.py
.venv-gpu/bin/python scripts/check_qemu_systemos.py --check-only
```

The build selects the observed SystemOS UUID and keeps ignition enabled. The
volume mounts read-only over `/` as a native union. Its mounted device matches
the signed policy, and the original OS root passes a second authorization check.
Original dyld maps the shared cache; its live 512-byte header matches the local
original file. Execution reaches `launchd` main, where 16 entry bytes match the
original executable. The check follows the initial demand-page fault and stops
at that entry. The wrong-UUID control stops before mounting. See
[the SystemOS result](../reports/public/ios16-qemu-systemos-entry.json).

Add the native development KeyStore state service:

```sh
.venv-uefi/bin/python scripts/check_keystore_host.py
.venv-uefi/bin/python scripts/build_qemu_keystore.py
.venv-uefi/bin/python scripts/build_qemu_keystore.py --closed
.venv-gpu/bin/python scripts/check_qemu_keystore.py
.venv-gpu/bin/python scripts/check_qemu_keystore.py --check-only
```

Both classes compile against Darwin 22; all 168 service and 186 user-client
dispatch slots read back. ASan/UBSan checks the protocol, identity withdrawal
and incomplete descriptor writes. In QEMU, original launchd runs all 20 userspace
crypto self-tests, then keybagd accepts the open handshake and both system-handle
queries. The closed control refuses the client. Each run stops at that result.
See [the KeyStore result](../reports/public/ios16-qemu-keystore-entry.json).

This service describes an unlocked VM without a passcode or keybag. Software key
encoding uses its public development identity and provides no hardware data
protection. Attach volatile Data to continue through the keybag boot task:

```sh
.venv-uefi/bin/python scripts/prepare_qemu_data.py
.venv-uefi/bin/python scripts/build_qemu_data.py
.venv-uefi/bin/python scripts/build_qemu_data.py --wrong-seed
.venv-gpu/bin/python scripts/check_qemu_data.py
.venv-gpu/bin/python scripts/check_qemu_data.py --check-only
```

The separate 2 GiB seed preserves all 198 initial Data entries and adds a
root-owned `keybags/` directory and empty `KeyBagKeys` plist. Full readback and
the APFS checker verify the contents, ownership and modes; two builds match.
The VM device tree declares the absence of effaceable storage. No passcode,
Apple keybag or device secret is generated.

Original APFS mounts this volume read-write at `/private/var`. RamBlock records
successful reads and writes; OS and SystemOS remain read-only. Original keybagd
completes `MKB_INIT`, then usermanagerd creates kernel personas and completes
`UMD_INIT`. The check stops there. A kernel compiled for a different seed hash
refuses the input before mounting. See
[the Data result](../reports/public/ios16-qemu-data-entry.json).

That candidate keeps Data in RAM. To save its writes across VM boots, build the
separate persistent candidate:

```sh
.venv-uefi/bin/python scripts/check_qemu_store_host.py
.venv-uefi/bin/python scripts/build_qemu_store.py
.venv-gpu/bin/python scripts/check_qemu_store.py
.venv-gpu/bin/python scripts/check_qemu_store.py --check-only
```

It uses a third VirtIO device backed by a local overlay file. The driver checks
its identifier, exact capacity and FLUSH support before accepting it. Each write
waits for a completed flush. The 23 transport sanitizer cases include malformed
completions, timeouts and failed flushes.

The runtime check starts two fresh VMs. After the first reaches `UMD_INIT`, it
stops QEMU with `SIGKILL`. The second resumes the same overlay without resetting
it and completes the same keybag and persona tasks. Independent APFS readback
finds the same persona identifiers in both snapshots. An incorrect device
identifier and a valid-CRC header for a different seed are refused before Data
mounting; both rejected files remain byte-for-byte unchanged. See
[the persistence result](../reports/public/ios16-qemu-store-entry.json).

The runner creates a new private overlay for each test under
`build/cph2653-qemu-store-entry/`. OS and SystemOS stay read-only. This exercises
VM-file persistence; physical UFS, hardware data protection and the graphical
interface still need implementation and validation.

Continue through the original system services and check the per-CPU regression:

```sh
.venv-gpu/bin/python scripts/build_qemu_services.py
.venv-gpu/bin/python scripts/build_qemu_services.py --check-only
```

This entry builds both persistent kernels and runs the original exec,
crash/cold-resume and service checks. `--record-existing` validates completed
stages without rerunning the VMs. Both kernels compile the actual mbuf consumer
with an isolated copy of the pinned per-CPU header. The positive kernel applies
the exact Darwin 22 patch; the control retains the original header. Neither
build replaces the shared native kernel objects or its link file list.

The service check follows original launchd through its signed configuration
cache and early boot, then observes original SpringBoard, logd, notifyd and
amfid executing in EL0. SpringBoard's process UUID must match the executable
extracted from the pinned iPhone images. The fixed mbuf statistics function
must return with an empty secondary CPU range; the old consumer must reproduce
its kernel data abort. Data and both verified read-only system mounts remain
checked throughout. Kernel state is sampled at syscall entry; user output
checkpoints read only user memory. The bounded run finishes at a kernel
checkpoint before reading the final storage state. The recorded run covers
30,001 checkpoints and four successful mbuf calls, while the old consumer
faults on its first call. The original display client still reports an unavailable
IOMFB. The graphical interface and complete system boot remain unqualified. See
[the service result](../reports/public/ios16-qemu-services-entry.json) and
[the complete service stages](../reports/public/ios16-qemu-services-stack.json).

## Native system packages

After the native A830 prerequisites, build the native system integration with:

```sh
.venv-gpu/bin/python scripts/build_native_system_stack.py
.venv-gpu/bin/python scripts/build_native_system_stack.py --check-only
```

The nineteen stages build two isolated kernels and local boot/root packages.
Each kernel has 127 source/binding objects, 29 original iPhone components and
64,635 independently checked pointer sites. OS and SystemOS use signed,
read-only native UFS windows; the original Apple root-authentication result and
dyld ignition path remain present. The owner policy is a separate development
trust decision. The Data mount checks its exact seed, APFS device and mount result.
Development AES/KeyStore load before the existing storage/Data/input schedulers.
A rejected identity or security setup prevents those schedulers from running.

| Local output | Contents |
| --- | --- |
| `build/cph2653-native-system-bringup/boot.img` | Android v4 container with verified native kernel, A830 addon/trust and packed 2 GiB development Data; physical writes disabled at compile time |
| `build/cph2653-native-system-bringup/iphone-root.img` | 8,445,685,760-byte regular file containing the exact original OS/SystemOS windows and appended owner policies; no GPT |
| `build/cph2653-native-system-bringup-persistent/boot.img` | Separate kernel allowing an explicitly opened Data-overlay write window; both root media remain read-only |
| `build/cph2653-native-system-bringup-persistent/system-manifest.json` | Exact hashes, existing partition name, root/overlay geometry and minimum capacity; no partition creation or deployment |

Each new boot image is 95,072,256 bytes, within the captured 100,663,296-byte
`boot_a/boot_b` capacity. The FAT is 88 MiB. The large policy hash tables live in
the root-image suffix; the kernel fixes the entire container digest and loads an
immutable snapshot before preparing any root window. Existing owner RSA
signatures and per-block verification remain required. The original volume bytes
are unchanged. Format bounds pass 4,117 host cases; 13 cases execute the actual
loader with explicit read/VM peers, including allocation/protection failures,
changed headers/data, chunk bounds and retained immutable snapshots.

The capture contains no `unixnu` root partition. These local packages describe
the required layout without creating a partition, changing GPT or deploying an
image. The older 160 MiB A830 development FAT remains preserved as local evidence;
the new native system packages use the capacity-checked format above.

The boot image and original root image are separate files. The persistent-capable
variant requests an overlay at the end of the selected `unixnu` partition, clear
of the root image, a 4 MiB guard and the existing 1 GiB end reserve. The window is
limited to one quarter of the partition. Reversed/overflowing geometry is refused.
Only a matching seed header resumes Data; neither package automatically resets
an existing or foreign overlay. Physical persistence has not been qualified.

Both kernels select
[`0030-ios16-hid-event-lifecycle.patch`](../patches/oneplus13/0030-ios16-hid-event-lifecycle.patch)
through `scripts/build_hid_lifecycle.py`. It replaces only the EventDriver
object in an isolated input archive, preserving the original input, A830 and
QEMU baselines. The linked class has a compiler-derived 560-byte instance,
the measured 264-byte original parent and the same 219 virtual slots. Both
linked and prelinked kernels read back that table and allocation extent.

The overlay serializes startup, event dispatch and stop on the provider
workloop. Stop closes admission before waiting for the gate. Reentrant stop
defers the single original parent cleanup until the source startup/dispatch
frames return; failed original initialization cannot start. Thirty ASan/UBSan
source cases include concurrent starts, concurrent stop/dispatch and recursive
callbacks. Twenty-five native instruction cases execute the original full
EventDriver/EventService init/stop and the used event accessors/default dispatch.
Both host and native controls reproduce the old direct-stop overlap.
See [the source result](../reports/public/ios16-hid-lifecycle-source.json) and
[the native result](../reports/public/ios16-hid-lifecycle-kernel.json).

Ten separate instruction cases execute the complete original init, stop and
free bodies, including the typed 376/512-byte private expansions, three timers
and observed owned-field/gate/workloop cleanup. An injected null-expansion
failure still faults in original free, so the production initialization,
provider and workloop pins remain. These checks use explicit public IOKit and
native IOService peers. Full original startup and final event delivery remain
peers in the selected-driver check. Draining the source frames does not qualify
the original producer callback, matching/client/async lifetime, restart or final
release. See [the original-body result](../reports/public/ios16-hid-original-lifecycle.json).

The calendar backport preserves the pinned ArmDTPlatform revision. It publishes
`IORTC` only when no RTC node exists, and uses a real registered clock when valid
or the kernel build date minus one day as a lower bound. This supplies no
battery-backed clock. Its parser and actual clock callback bodies pass 598
sanitizer cases.

The native entropy adapter uses the captured `qcom,trng` resource at
`0x10c3000` and the original iPhone client's `AppleVirtIOEntropy` class search,
selector 0 and 32-byte output. It performs no clock/configuration writes, refuses
partial or stuck output and restricts opens to root. Its 364 host cases and the
original client call instructions pass local checks; the hardware and entropy
rate remain unqualified. The read-only, 8-byte `kern.prng.user_reseed_count`
increments only after a real nonempty request completes the unchanged original
PRNG reseed implementation. Four thousand concurrent calls and refusal controls
pass. This counter shares the original PRNG tree rather than declaring a second
node named `kern.prng`. The unchanged iPhone corecrypto supplies 99 scheduled
and per-pool observations for 32 pools. Read-only `pool0` aliases connect the
original user's `kern.prng.pool%zu.%s` queries to corecrypto's `pool_0` child
lists, preserving both names and the actual original counters.

An additional instruction check executes native early/dynamic registration,
OID allocation, name lookup and installed handlers. All 228 diagnostic paths
resolve, all 99 original counters are read, and 40 synthetic entropy requests
exercise real original scheduled/pool accounting. One actual original user
reseed increments only its counter. Output-error controls also pass. This is
model evidence with explicit entropy/lock/copy peers; saved-seed lifecycle and
physical persistence remain unqualified.

The persistent-capable package explicitly selects `dodge-seed-sync=1`. On close,
the native VFS hook checks the exact original seed path, verified writable APFS
Data mount, root ownership, mode 0600, one link and 32-byte length. It requests
file fsync, directory fsync and `F_FULLFSYNC`; unsupported flushes and I/O errors
remain failures. Ordinary close, lock release and vnode cleanup still run. The
unchanged original program ignores close errors, so four read-only, 4-byte
diagnostics retain the selected attempt/completed/failed counts and last errno:
`kern.dodge_seed_sync_attempts`, `kern.dodge_seed_sync_completed`,
`kern.dodge_seed_sync_failed` and `kern.dodge_seed_sync_last_error`.
Completed means the filesystem accepted full synchronization. The hook passes
56 sanitizer cases and ten actual native close/diagnostic instruction cases.
Two complete original saver instruction runs include partial writes, temporary
clearing and a failing full-sync case. VFS and syscall peers remain explicit.
The original program still truncates before writing; this change adds no atomic
replacement or guarantee that an old seed survives a crash during the save.
Fresh boot entropy remains independently required; saved seeds add input.

The actual EFI handoff and all 18 original iPhone crypto POST tests pass in the
CPU model for each package. Native startup/refusal and original entropy-client
instruction checks also pass; MMIO, registry, scheduler and syscall boundaries
remain explicit peers. These are local build/model results, separate from native
boot or a working graphical system. The default payload, source pins, private
platform seed and firmware-specific memory patch are retained.

After the persistent QEMU prerequisites, check the saved-seed filesystem path:

```sh
.venv-gpu/bin/python scripts/build_qemu_seed_sync.py
.venv-gpu/bin/python scripts/check_qemu_seed_sync.py
.venv-gpu/bin/python scripts/check_qemu_seed_sync.py --check-only
```

This isolated VM kernel uses the same close hook with a separately selected
guard requiring the existing QEMU software AES/KeyStore readiness and virtual
development identity. The native owner guard and both native packages remain
unchanged. Original iPhone `prng_seedctl` executes file/directory fsync and
`F_FULLFSYNC` through actual APFS, VFS and the VirtIO-backed Data overlay.
Both observed boots complete one synchronization with no error. After actual
SIGKILL, an independent APFS reader finds the private 32-byte file. The cold VM
resumes without reset; the original utility's real read returns those exact
bytes, compared in memory only. Compiler-derived saved-state layout and the
caller's stack distinguish its shared-cache read return. Seed contents and
seed digests stay out of the public report. See
[the VM result](../reports/public/ios16-qemu-seed-sync-entry.json).
This checks the saved-file path; entropy-provider/diagnostic compatibility and
the utility's overall exit status are separate. It does not test a crash during
the original truncation/write, physical UFS durability or hardware data protection.

## Wi-Fi transport source

```sh
.venv-gpu/bin/python scripts/prepare_dodge_wifi.py
.venv-gpu/bin/python scripts/build_wifi_transport.py
.venv-gpu/bin/python scripts/build_wifi_transport.py --check-only
```

The first command checks facts from the existing capture without contacting a
phone. A separate source reference selects the public portable PaganiWifi
protocol implementation at `c888efd3`; existing source pins stay unchanged.
The board adaptation removes the donor's seventh antenna-share supply:
CPH2653 has six WLAN supplies and no `vdd-wlan-ant-share`. Its eight selected
pins, including CLKREQ from the active pinctrl group, seven PCIe0 register windows,
endpoint stream selection and all 128 PHY writes match the captured tree. Shared UFS rail S7I is never lowered or disabled.
Only explicit survey, power and Gen1/Gen2 link stages are admitted; Gen3 requires
additional voltage votes that this integration does not own.

Eight ASan/UBSan suites execute the actual MHI, firmware loader, DMA allocator,
PMIC, RDDM, FAT and startup sources with synthetic files and controller peers.
The firmware checks cover 407 cases; the board/startup fixture covers 21,133.
An explicit cache teardown validates the whole batch, clears allocated bytes
and frees ownership after all borrowers stop. Fixture caches are released before
reinitialization and exit; leak detection remains enabled. The native build
produces ten arm64/iOS16 objects in `libDodgeWifiTransport.a`.
See [the source result](../reports/public/ios16-wifi-transport.json).

This archive is separate from the kernel. Kernel registration/worker scheduling,
DMA/SMMU ownership, MSI, real firmware and the iPhone wireless-framework ABI still
need integration. No iPad wireless frontend, foreign binary binding or Linux
wireless runtime is imported. The host-only CI command is
`scripts/build_wifi_transport.py --host-only`; it needs Clang sanitizers and
mtools, without captured firmware or a native SDK.

## Remaining source integration

The source preparation phase still has implementation work. A local PASS does
not turn the following gaps into hardware-only tests. Finish the relevant
source integration and local checks before asking for device testing.

| Area | Work still needed |
| --- | --- |
| Native system startup | The native root/SystemOS/Data source and two local packages are connected. Complete transport reset/recovery and persistent-installation/seed lifecycle policy; qualify the original filesystem/client lifetime and physical Data path. |
| Display and Metal | Complete original display/client/IOSurface lifetime and Metal discovery integration. Derive the board's framebuffer and panel power contract; current static GOP declarations and host pipeline translation do not establish a working desktop. |
| Input | The selected native EventDriver now serializes source startup/dispatch/stop. Complete shared clock/power and reset/DMA ownership, target orientation, full original startup/producer/client/matching lifetime and final release. Current source intentionally retains lifecycle pins, mappings and shared votes after hardware attempts. |
| Power and security | Derive the SM8750 security-state mapping and implement its PMGR provider. Battery, charging, thermal management, sleep and hardware key/nonce/rollback policy are still open. |
| User entropy | Reseed accounting, original pool observations and selected saved-seed full synchronization are connected locally. Complete crash/replacement and installation policy; qualify hardware entropy, native service dispatch and physical persistence. |
| Other peripherals | Wi-Fi portable power/link/protocol source is adapted separately. Complete its kernel worker, DMA/MSI/firmware and iPhone interfaces, plus Bluetooth, audio and cellular transports. These areas still have no functional board drivers. |

The initial CPU path remains single-core. SMP, PSCI, interrupts, timer behavior,
physical DMA/cache visibility, scanout and GPU output require their own device
observations after the corresponding source work. All current development
images and original inputs stay local; no phone operation is part of this phase.

## System and Data images

```sh
.venv-uefi/bin/python scripts/fetch_ios_inputs.py --volumes
.venv-uefi/bin/python scripts/prepare_ios_volumes.py
.venv-uefi/bin/python scripts/prepare_root_image.py
.venv-uefi/bin/python scripts/prepare_initial_data.py
.venv-uefi/bin/python scripts/check_system_inputs.py
```

| File | Contents |
| --- | --- |
| `build/ios16-root-image/iphone-root.img` | Read-only OS/SystemOS windows |
| `build/ios16-initial-data/initial-data.tar` | Initial Data contents |
| `build/ios16-data-apfs-volatile/data.dbr` | 2 GiB Data seed for the sparse RAM-backed route |
| `build/ios16-data-apfs/data.dbr` | Separate 3 GiB Data seed for later persistent-storage work |

## Reports

Build scripts write local reports to `reports/*.json`. Published copies in
`reports/public/` omit local machine paths. The
[index](../reports/public/index.json) stores original and published hashes.
Dependency hashes inside a report refer to the original local reports. Earlier
versions remain available through the previous index linked from the current one.
Snapshots record the source and host settings of their original run; CI checks
the current source tree.
`retained_public_snapshot` marks older published evidence whose local candidate
has been retired; its original digest stays in the index.

Sources, firmware, backups, keys, environments and build outputs stay in ignored
local directories. See [NOTICE.md](../NOTICE.md) for licenses and source credits.
