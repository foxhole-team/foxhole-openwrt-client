# Native transaction utility

This is a separate APK-tools 3.0.5 executable with the FoxHole transaction ABI 1. It changes only the fixed FoxHole BASE package and up to three explicitly approved new protocol packages. It does not replace the system `apk` executable.

The tracked archive is source code: exactly 416 regular files and the original `src/apk-static.c → apk.c` link, inside a pinned archive. The public exporter still refuses filesystem symlinks and arbitrary archives. `tools/check-transaction-source.py` admits only this exact archive and its one source-link role.

The normal executable excludes the `FOXHOLE_TRANSACTION_QA` variant. Its only dynamic runtime dependencies are musl `libc.so` and `libgcc_s.so.1`; the OpenWrt package declares `+libgcc`.

## Corresponding source

Complete source inputs are supplied separately as `foxhole-apk-transaction-v1-source-inputs.tar.gz` (7,630,415 bytes, SHA-256 `df92280ae325021242d49fde13b6367f3f5460ce81364d5f62d4579c3b1023ba`). This source-input asset contains the complete fork/upstream APK sources, Mbed TLS 3.6.6 including its framework, Zlib 1.3.1 source, the matching OpenWrt Zlib recipe and four patches, original notices, and public SDK provenance. The final executable build and package-install scripts are in this same public source delivery.

The standalone executable uses GPL-2.0-only. Mbed TLS and its framework use their GPL-2.0-or-later version 2 option; their complete original dual-license texts are retained. Zlib retains its original license. These source inputs accompany the executable release as downloads; they are not installed in the router's BASE filesystem. No future publication URL is assumed.

## Rebuilding the recorded normal target

Use the matching OpenWrt 25.12.5 SDK, revision `r33051-f5dae5ece4`, with GCC 14.3.0/musl and its self-contained host Meson/Ninja tools. The exact recorded `include/version.mk` SHA-256 is in `SOURCE.json`. The SDK remains read-only. Linux needs CMake, Python, pkg-config and the SDK compiler/ar/strip tools.

The original build linked the official Zlib 1.3.1-r1 developer inputs. Supply the verified developer archive for the requested architecture. Those library/header bytes are build inputs, not a substitute for corresponding source: the separate source-input asset contains the full Zlib source, package recipe and patches needed to rebuild that SDK package. Developer archive identities are explicit in `build.py` and in the source-input recipe. Unknown headers/libraries are refused.

For x86/64:

```sh
python3 native/transaction/build.py \
  --sdk /sdk --architecture x86_64 --work /out \
  --source-inputs /inputs/foxhole-apk-transaction-v1-source-inputs.tar.gz \
  --zlib-dev /inputs/verified-zlib-x86_64.tar.gz \
  --expected-manifest /inputs/transaction-tool.json
```

For mediatek/filogic, use `--architecture aarch64_cortex-a53` and its matching developer archive. Use a fresh work directory outside this source repository. The recorded layout used `/sdk` and `/out`; different tool versions or build paths require an actual comparison, not a reused identity claim.

The script verifies the source inputs, builds static Mbed TLS, configures the normal APK-tools fork with Meson `--buildtype=release`, and runs Ninja with two jobs. It uses `SOURCE_DATE_EPOCH=1793145600`, disables documentation/help/Lua/Python/tests/zstd, selects `wget` plus the Mbed TLS crypto backend, and never defines the QA macro. It strips with `--strip-unneeded` and writes level-9 gzip with zero timestamp and the recorded Unix OS byte. `--expected-manifest` requires the rebuilt ELF and gzip identities to equal the recorded target. Without it, the emitted identities describe a new build and do not qualify it for packaging. Compiler/compressor changes must not be relabeled as the previous artifact.

## SDK package inputs

The BASE Makefile requires four explicit variables:

- `FOXHOLE_TRANSACTION_MANIFEST_INPUT`
- `FOXHOLE_TRANSACTION_MANIFEST_SHA256`
- `FOXHOLE_TRANSACTION_X86_GZIP_INPUT`
- `FOXHOLE_TRANSACTION_ARM64_GZIP_INPUT`

`tools/check-transaction-inputs.py` verifies the closed ABI/source manifest, exact two targets, compressed and uncompressed sizes/hashes, bounded gzip expansion, ELF architecture/musl interpreter, normal applets, and the `libc.so`/`libgcc_s.so.1` closure. It installs only the verified bytes at the three fixed data names. Missing inputs, executable-path fields, extra targets, QA payloads and unverified source-build fallbacks are refused. Runtime gzip/ELF data never enters this Git/source tree.

Static build/input verification does not prove native root/layout behavior, target runtime, rollback, router resources or authenticated tunnel traffic. Those require the separate target and genuine updater qualification for the exact artifacts.
