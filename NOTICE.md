# Licenses and third-party sources

Local files use the root [BSD-2-Clause license](LICENSE) unless a file carries a
different SPDX identifier or license notice. Patches keep the license of their
upstream source.

## License texts

| License | Files |
| --- | --- |
| BSD-2-Clause | [LICENSE](LICENSE); local scripts and Mu-Silicium-derived changes |
| BSD-2-Clause-Patent | [Full text](LICENSES/BSD-2-Clause-Patent.txt); marked drivers and UniXNU-derived code |
| MIT | [Full text](LICENSES/MIT.txt); marked GPU fragments, host peers and Go helper |
| GPL-2.0-or-later | [GPL version 2](LICENSES/GPL-2.0.txt); `tools/ApfsExtract.cpp`, `ApfsDataInventory.cpp` and `ApfsDataVerify.cpp` |
| GPL-2.0 | [Full text](LICENSES/GPL-2.0.txt); `patches/apfsprogs/` |
| APSL-2.0 | [Full text](LICENSES/APSL-2.0.txt); Apple source changes marked APSL |
| BSD-3-Clause | [Full text and Apple LZFSE notice](LICENSES/BSD-3-Clause.txt); applicable Apple/BSD files |

The original [GENI component license](drivers/DodgeInput/geni/LICENSE) is kept
alongside the local derivative. File notices take precedence over the table.
Dependencies restored by setup scripts retain their own licenses.

## Upstream projects

Exact revisions, patch hashes and input identities are recorded in
[upstream.lock.json](upstream.lock.json), [unixnu.lock](unixnu.lock) and the
dependency lock files.

| Project | Use |
| --- | --- |
| [Mu-Silicium](https://github.com/Project-Silicium/Mu-Silicium) | UEFI board support, memory map and firmware packaging |
| [UniXNU](https://github.com/UniXNU/UniXNU) | Build driver, DarwinBoot, XnuPrelink, native driver interfaces and RamBlock |
| [VirtioMmioBlock](https://github.com/UniXNU/VirtioMmioBlock) | Read-only QEMU storage transport with the iPhone storage ABI |
| [Apple XNU](https://github.com/apple-oss-distributions/xnu) | Darwin 22 kernel; selected VFS backport from XNU 10063.141.1 |
| [SM8750 common](https://github.com/IssacL04/UniXNU-sm8750-common) | SoC support and topology |
| [Pagani drivers](https://github.com/IssacL04/UniXNU-Pagani-Drivers) | Peripheral protocols, input code and console renderer |
| [OnePlus 13T device](https://github.com/IssacL04/UniXNU-Pagani_SM8750) | Board integration reference |
| [OnePlus 13T A830 device](https://github.com/Shad0w23333/UniXNU-Pagani_SM8750) | Standalone A830 board and startup reference |
| [Native Adreno830](https://github.com/Shad0w23333/Adreno830) | Standalone Gen8 source candidate; MIT, copyright 2026 NativeAdreno contributors |
| [Adreno740](https://github.com/IssacL04/Adreno740) | A830 backend and resource management |
| [AdrenoMetal](https://github.com/IssacL04/AdrenoMetal) | Metal frontend and calling-thread compilation backport from `c1351337` |
| [AdrenoFirmware](https://github.com/IssacL04/AdrenoFirmware) | Firmware parser and Gen8 interfaces |
| [A830 build reference](https://github.com/IssacL04/UniXNU_Enc3l) | Build integration and host tests |
| [metal2vulkan](https://github.com/steelbrain/metal2vulkan) | AIR translation |
| [Mesa](https://gitlab.freedesktop.org/mesa/mesa) | Turnip, NIR and IR3 |
| [LZFSE](https://github.com/lzfse/lzfse) | Local decompression tool |
| [unifdef](https://github.com/fanf2/unifdef) | Header preprocessing |
| [iig-port](https://github.com/Nyktis/iig-port) | Interface generator; MIT, copyright 2026 iig-port contributors |
| [apfs-fuse](https://github.com/sgan81/apfs-fuse) | GPL read-only extraction and verification library |
| [go-apfs-v2](https://github.com/deploymenttheory/go-apfs-v2) | MIT APFS image writer |
| [apfsprogs](https://github.com/linux-apfs/apfsprogs) | GPL APFS checker |
| [Fajita device](https://github.com/johnpanos/UniXNU-fajita) | Data seed format reference |
| [Theos SDKs](https://github.com/theos/sdks) | Local cross-build headers and link stubs |
| [Unicorn](https://github.com/unicorn-engine/unicorn) | Host-only ARM64 instruction model |

Apple's [IOStorageFamily](https://github.com/apple-oss-distributions/IOStorageFamily),
[IOHIDFamily](https://github.com/apple-oss-distributions/IOHIDFamily) and
[IOGraphics](https://github.com/apple-oss-distributions/IOGraphics) provide public
ABI reference headers under their file notices. The build tools also use
Apple's [dyld cache format](https://github.com/apple-oss-distributions/dyld) and
[libutil mount-option parser](https://github.com/apple-oss-distributions/libutil).
The latter retains the BSD-3-Clause notice of the Regents of the University of
California.

Linux and OnePlus kernel register references are listed in the input/GPU/clock
sections of `upstream.lock.json`. Their source and notices stay with the local
reference checkouts. Rust, LLVM, Khronos tools and other downloaded build tools
keep their upstream licenses.

## Firmware and system inputs

Apple system contents, OnePlus firmware, microcode and SDK files are obtained
locally. This repository stores their provenance, metadata and hashes, together
with the extraction code. Original inputs, patched binaries, generated images,
private platform identities and phone backups remain outside the public file set.

The stock firmware delta credits come from the pinned
[Device-Binaries/dodge README](https://github.com/Project-Silicium/Device-Binaries/blob/9f4dbfd7d61acdae69fd5bb48720ce7e53711e25/dodge/README.md).
