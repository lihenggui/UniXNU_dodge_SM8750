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

The [official guide](https://unixnu.com/porting/) was reviewed on 2026-11-11
against UniXNU `13d0779e2ccd30d3caa1f8c9a15202730feace67`. Follow its order:
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
```

Check the standard packaging entry point after fetching the sources:

```sh
PATH="$PWD/.venv-uefi/bin:$PATH" scripts/package.sh --check --no-deps --os 16 \
  --out build/unixnu -j 4
```

This resolves the iPhone profile and its 61 patches. The full `release` build
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
Continuing through dyld, mounting Data and starting system services remain open.

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

Sources, firmware, backups, keys, environments and build outputs stay in ignored
local directories. See [NOTICE.md](../NOTICE.md) for licenses and source credits.
