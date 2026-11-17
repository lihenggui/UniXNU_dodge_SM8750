# OnePlus 13 iOS port

Device configuration, drivers and build scripts for bringing iPhone iOS to the
OnePlus 13 CPH2653 (dodge, SM8750).

The current target is iPhone10,3 running iOS 16.7.16 / 20H392, using arm64 and
Darwin 22. The UEFI and kernel build locally. Full system boot and hardware
bring-up are still in development. The port follows the
[UniXNU porting guide](https://unixnu.com/porting/).

The native Adreno 830 build includes the CPH2653 board adapter, iPhone IOSurface
handling, Turnip and Metal. Its userspace adapters share compiled shaders between
pipeline caches and connect tile pipelines to the pinned runtime.

The native system source now connects owner-verified UFS OS/SystemOS, Data,
development AES/KeyStore and the captured Qualcomm TRNG. Separate read-only and
persistent-Data-capable kernels produce local boot/root packages. The persistent
variant also synchronizes the original private saved seed and exposes flush
failures through read-only diagnostics. These builds
retain the iPhone source pins and firmware memory patch; native boot, graphics
and hardware security remain unqualified.

Both native kernels also select an HID EventDriver lifecycle overlay. It
serializes startup, dispatch and stop, closes admission before waiting, and
defers cleanup through a software event after the enclosing workloop action
returns. It closes its own report interface before parent cleanup and completes
termination notifications without retaining caller output pointers. Full original
startup, matching, producer/client lifetime and final release still need work.

A separate Wi-Fi transport archive adapts the captured six-rail power topology
and PCIe PHY sequence. Its protocol and ownership checks run on the host;
kernel networking and original iPhone wireless clients still need integration.

Separate QEMU builds mount the original iPhone OS and SystemOS images, run the
original dyld, launchd and system services, including the SpringBoard process.
They complete the userspace crypto and keybag/persona initialization tasks.
Data survives a forced VM stop and cold resume. The graphical interface and
complete system boot are still being brought up.
An isolated seed fixture also verifies that the original iPhone utility saves
through APFS full sync and reads the same private bytes after cold resume.
See [GPU builds](docs/bring-up.md#driver-builds) and [QEMU entry](docs/bring-up.md#qemu-entry).
See [native system packages](docs/bring-up.md#native-system-packages) for the new
source build and its local checks.
The guide lists [remaining source work](docs/bring-up.md#remaining-source-integration)
and the [current upstream review](docs/bring-up.md#upstream-review).

## Getting started

Use a Linux host with Python 3.12. See [the build guide](docs/bring-up.md) for
system packages and toolchain setup.

```sh
python3.12 -m venv .venv-uefi
.venv-uefi/bin/python -m pip install -r requirements-host.lock
.venv-uefi/bin/python scripts/prepare_sources.py --apply
cp local.toml.example local.toml
```

Builds use four jobs and inherit the host's resource limits.

## Repository layout

| Path | Contents |
| --- | --- |
| `board.toml`, `configs/`, `dts/`, `targets/` | Board and iPhone target configuration |
| `drivers/`, `profiles/`, `patches/` | Drivers, OS-specific interfaces and source patches |
| `scripts/`, `tests/`, `tools/` | Setup, builds, extraction tools and tests |
| `hardware/`, `proprietary-files.txt` | Hardware data and input hashes |
| `upstream.lock.json`, `unixnu.lock`, dependency locks | Source and dependency versions |
| `porting.toml` | Component status and remaining work |
| `reports/public/` | Published build and test reports |

## Local files

Firmware, Apple system files, phone backups, private keys, build outputs and
toolchains stay in ignored local directories. Setup scripts fetch the pinned
sources into `sources/` and `uefi/`; builds write to `build/`.

The [report index](reports/public/index.json) records the original and published
hashes. See [report handling](docs/bring-up.md#reports) for details.

## License

See [NOTICE.md](NOTICE.md) for file licenses and third-party sources. License
texts are included in `LICENSE`, `LICENSES/` and component license files.
