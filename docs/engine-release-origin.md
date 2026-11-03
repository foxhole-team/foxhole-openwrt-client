# Core version and router delivery release

The Core version identifies the qualified native producer. The router release
containing its packages can have a different version. For example, Core 1.0.2
artifacts are delivered in the published OpenWrt client 1.0.3 release.

Each catalog entry binds its exact package and index to one immutable HTTPS
release directory in `foxhole-team/foxhole-openwrt-client`. The consumer checks
the repository, numeric release tag, package name, package version, manifest
digest and index filename. It does not infer the directory from the Core
version. Package signatures, binary checksums, slot identities, architecture,
producer and legal provenance checks remain required.

The RAM launcher selects the exact current catalog entry for its immutable
slot. If that slot is retained after a catalog update, it can use its existing
validated registry entry. It verifies the slot and uses the package/index
delivery directory for the raw binary URL. A warm cache retains the same size,
ownership, permissions and checksum checks as a new download.

RAM package builds default to package release 2; FLASH retains release 1. The
Core version and native binary bytes remain unchanged. A changed RAM launcher
gets a new executable digest and immutable slot identity. Its new APK, index
and catalog require fresh canonical packaging and signatures. Existing FLASH
APKs can be reused byte for byte; the shared index digest changes when the RAM
packages change. Every raw binary referenced by the delivery directory must
actually be present there before production use.

RAM storage describes the volatile raw binary. Normal engine installation
keeps its small launcher, slot metadata and notices under `/usr`, and its
registry under `/etc/foxhole`. This fix adds no metadata autoload feature and
does not change the existing restriction on engine transactions while BASE is
running from a RAM overlay. It also adds no minimum BASE version dependency to
the host APK database: that database can describe an older BASE beneath an
active verified RAM overlay. Compatibility is checked against the active
consumer and the complete signed catalog; failure remains explicit.
