# RAM recovery HTTPS fetch helper

This private product executable is derived from OpenWrt 25.12.5's pinned
uclient-fetch source. `SOURCE.json` records the corresponding upstream files and
matching public header revisions. Original notices remain in each source file.

Compile `uclient-fetch.c` and `progress.c` with the matching OpenWrt SDK compiler,
these local headers, and the matching libubox/ustream public headers. Link against
matching unstripped development `libuclient.so` and `libubox.so.20260213`; installed
runtime libraries can be sectionless and unsuitable as development inputs. When
needed, build only the matching upstream core library targets for linking, retain
their SONAMEs, and never deploy them. The existing system libraries, libustream
TLS implementation and CA trust remain authoritative. No Core or VPN module
compilation is needed. Keep compiled executables outside this source tree.

The Makefile requires explicit SDK/header/link-library paths and a qualified
`RECOVERY_PAGE_SIZE=4096`. For the current Filogic target use
`RECOVERY_ARCH_CFLAGS=-mcpu=cortex-a53`. The recipe enables PIE, strong stack
protection, SDK fortify level 1, full RELRO, NOW, NX stack and relative relocations.
Its 4 KiB segment alignment is scoped to the measured 4 KiB target; it does not
qualify 16/64 KiB systems. Reuse completed development libraries for a helper
relink; do not rebuild them for a linker-flag or metadata correction.

The interface is deliberately limited:

```
foxhole-ram-fetch [--ca-certificate /protected/public-ca.pem] https://host/path
foxhole-ram-fetch --github-release https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/TAG/ASSET
```

Archive data goes to stdout with a 60-second timeout per HTTP request. The bootstrap's
existing owned capture adds the total deadline and byte limit. Initial HTTP URLs,
credentials, proxy settings, custom headers, additional URLs, POST and insecure
certificate options are refused before network dispatch. The direct HTTPS mode
allows up to three absolute redirects on the original authority.

GitHub mode derives the official tag API endpoint from the stable versioned URL.
The existing system ucode interpreter checks the bounded metadata, exact repository,
tag, filename, numeric asset ID and uploaded state. The helper requests that ID
as an octet stream with system CA trust. It allows one HTTPS handoff to `release-assets.githubusercontent.com`,
under repository ID `1361759440`. The CDN resource has a UUID and the signed
disposition names the requested BASE or architecture-specific bank. The helper
validates the certificate and hostname on each connection. It does not persist
or log the temporary CDN URL. The loader checks the exact signed archive size,
SHA-256 and native APK signature before extraction or activation.

Host policy tests compile the actual policy header. They do not qualify target
linking, TLS, redirects, native APK verification, low-memory boot or reboot. Those
checks must use the actual built helper and signed recovery bank. A recovery bank
URL or future artifact digest must never be filled from a guessed release.
