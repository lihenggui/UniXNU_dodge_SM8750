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
against UniXNU `215672be984f511b0923cbc120ea24bb48fef87e`. Follow its order:
resolve the board and OS profile, verify memory and firmware, build platform
services, then add storage, display, input and GPU support. Keep host results
and device observations separate in [porting.toml](../porting.toml).

Recent mainline changes add `firmware_tools` for staging board-extracted files
under a Data addon's `firmware/` directory, plus Mesa and macOS changes. This
checkout keeps the source versions in the lock file. Its GPU microcode is
embedded locally by the board build described below.

## Host setup

The existing builds used Ubuntu 22.04 / WSL and Python 3.12. CI runs on
Ubuntu 24.04. Scripts use four jobs and inherit host resource limits. The
20 GiB limit recorded in older reports describes that build machine.

Install system packages:

```sh
sudo apt-get install build-essential clang-14 lld-14 llvm-14 llvm-14-dev \
  libclang-14-dev uuid-dev libbsd-dev libssl-dev zlib1g-dev liblzma-dev \
  nasm mono-devel ca-certificates-mono device-tree-compiler mtools cmake \
  ninja-build unifdef pkg-config flex bison cpio rsync tcsh patch ruby
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

Create the GPU/model-test environment:

```sh
.venv-uefi/bin/python -m venv .venv-gpu
.venv-gpu/bin/python -m pip install --require-hashes -r requirements-gpu.lock
```

Each route keeps its own build directory. Use `--check-only` where supported
to check an existing build.

| Route | Command |
| --- | --- |
| Standalone native A830 source archive | `.venv-uefi/bin/python scripts/build_native_a830.py` |
| CPH2653 native A830 archive and isolated kernel | `.venv-uefi/bin/python scripts/build_native_a830.py --board --link` |
| A830, Turnip, Metal and display | `.venv-uefi/bin/python scripts/build_gpu_stack.py` |
| Read-only UFS and root storage | `.venv-uefi/bin/python scripts/build_storage_stack.py` |
| S3910 touch and iPhone HID | `.venv-uefi/bin/python scripts/build_input_stack.py` |
| APFS Data image and RamBlock | `.venv-uefi/bin/python scripts/build_data_stack.py` |
| Data startup payload | `.venv-uefi/bin/python scripts/build_data_startup_stack.py` |
| PID 1 Data mount | `.venv-uefi/bin/python scripts/build_data_mount_stack.py` |
| Original crypto initialization | `.venv-uefi/bin/python scripts/build_crypto_stack.py` |
| Original crypto/POST model | `.venv-gpu/bin/python scripts/check_original_crypto_kernel.py` |
| GPU status at display time | `.venv-gpu/bin/python scripts/build_fresh_gpu_stack.py` |
| GPU mapped-resource lifetime | `.venv-gpu/bin/python scripts/build_mapped_lease_stack.py` |
| IOSurface task lookup | `.venv-gpu/bin/python scripts/build_surface_identity_stack.py` |
| IOSurface/import page matching | `.venv-gpu/bin/python scripts/build_surface_pages_stack.py` |

The standalone A830 route uses Shad0w23333's Gen8 driver and its matching SMMU
library. `python3 scripts/check_native_a830_host.py` runs its software-controller
tests. The driver compiles against Darwin 22 and binds the original iPhone accelerator
base. Both [13T implementations](https://unixnu.com/devices/models/oneplus13t)
remain references; the target identity and original components come from the
iPhone profile above.

For the CPH2653 board candidate, prepare the pinned local firmware first:

```sh
.venv-uefi/bin/python scripts/prepare_gpu_firmware.py
.venv-uefi/bin/python scripts/prepare_native_a830.py
.venv-uefi/bin/python scripts/check_native_a830_board.py \
  --firmware-dir build/cph2653-gpu-firmware
.venv-uefi/bin/python scripts/build_native_a830.py --board --link
```

`prepare_native_a830.py` checks the saved runtime DTB against
[hardware/dodge-native-a830.json](../hardware/dodge-native-a830.json). It records
register windows, GIC INTIDs, stream IDs, all six power bins including ACD values,
and the eight GPU temperature sensors. The firmware step needs the pinned vendor
and vendor_boot images; [hardware/dodge-gpu-firmware.json](../hardware/dodge-gpu-firmware.json)
records their hashes. Firmware and generated headers stay under `build/`.

The board build writes a 54-object archive and `mach.native-a830` under
`build/cph2653-native-a830-board/`. It reads every embedded firmware image back
from the linked kernel and preserves the three original iPhone accelerator aliases.
The explicit `dodge_native_a830_start(expected_soc)` entry uses `dodge-gpu-*`
arguments and runs synchronously once per boot. Its expected SoC ID must be
618 or 639 from the captured DT; S0 checks it against live SMEM. The DT ACTLR
value is `0x32b`; a future runtime experiment can request another value explicitly.

The existing Metal frontend's selectors 17/18, IOSurface leases and initialization
order still need integration with this backend. The isolated kernel needs the
original graphics prelink, POST seal and system image before boot preparation.
The default kernel selection stays on the existing route.

The firmware entropy route has three steps:

```sh
.venv-uefi/bin/python scripts/build_boot_entropy.py
.venv-gpu/bin/python scripts/check_boot_entropy_kernel.py
.venv-gpu/bin/python scripts/build_entropy_payload.py
```

Component status and remaining integration work are tracked in
[porting.toml](../porting.toml).

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
