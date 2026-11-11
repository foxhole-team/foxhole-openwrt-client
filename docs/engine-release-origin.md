# Core version and router delivery release

The Core version identifies the qualified native producer. The router release
containing its packages can have a different version. For example, Core 1.0.2
artifacts are delivered in the published OpenWrt client 1.0.3 release.

The current qualified 1.0.5 BASE delivery retains its immutable module origin
in the OpenWrt 1.0.4 release. This differs from older 1.0.3 regression fixtures.
The independent feed introduced by BASE 1.0.6 is described in
[Independent Core module updates](core-updates.md).

Each catalog entry binds its exact package and index to one immutable HTTPS
release directory in `foxhole-team/foxhole-openwrt-client` or the fixed Core
origin admitted by the new signed feed. The consumer checks
the repository, numeric release tag, package name, package version, manifest
digest and index filename. It does not infer the directory from the Core
version. Package signatures, binary checksums, slot identities, architecture,
producer and legal provenance checks remain required.

The RAM launcher selects the exact current catalog entry for its immutable
slot. Both the launcher and update-worker staging derive the raw binary URL
from the admitted index directory, rather than the Core version. If that slot
is retained after a catalog update, it can use its existing
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
registry under `/etc/foxhole`. The release-origin fix does not change the
existing restriction on generic engine transactions while BASE runs from a
RAM overlay. The new Core-only path uses its own managed generation proof.
Neither adds a minimum BASE version dependency to
the host APK database: that database can describe an older BASE beneath an
active verified RAM overlay. Compatibility is checked against the active
consumer and the complete signed catalog; failure remains explicit.
