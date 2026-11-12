# OnePlus 13 iOS port

Device configuration, drivers and build scripts for bringing iPhone iOS to the
OnePlus 13 CPH2653 (dodge, SM8750).

The current target is iPhone10,3 running iOS 16.7.16 / 20H392, using arm64 and
Darwin 22. The UEFI and kernel build locally. Full system boot and hardware
bring-up are still in development. The port follows the
[UniXNU porting guide](https://unixnu.com/porting/).

The native Adreno 830 development build includes the CPH2653 board adapter,
iPhone IOSurface producer handling, Turnip and Metal. The kernel, original
iPhone components, GPU addon and entropy/logger firmware build locally. QEMU
enters `bsd_init` with EL1 and 4 KiB page tables. Original AppleImage4, AMFI
and Sandbox register successfully. Separate QEMU storage builds mount the
original APFS root through an owner-signed block policy. With the original
filesystem decompressor, PID 1 enters the iPhone dyld and executes in EL0.
The software AES fixture lets dyld finish its Image4 query. A SystemOS union
build maps the original shared cache and reaches `launchd` main. The native
KeyStore fixture lets the original `keybagd` accept its development system handle;
the original userspace crypto self-tests pass. A separate RAM Data build lets
`keybagd` and `usermanagerd` complete early initialization. The persistent Data
build saves writes in a local QEMU file and resumes the same persona state after
a forced VM stop. Later services remain in development.
See [GPU builds](docs/bring-up.md#driver-builds) and [QEMU entry](docs/bring-up.md#qemu-entry).

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
