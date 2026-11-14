# RAM deployment

This installer prepares signed release APKs in a separate RAM package root. The host APK database, owner profiles, pairing, TLS identities and installed Hysteria module remain separate. Activation exposes only reviewed public paths; it never mounts a package database or private configuration directory.

A root-owned active receipt distinguishes this deployment from a flash package upgrade.
Legacy or unmanaged RAM roots reject ordinary package/engine mutations, including
unqualified automatic updates. Native host APK queries still describe the retained
rollback package; they do not prove which RAM executable is active.

The separate **authenticated managed RAM update path** admits only the exact
verified active generation, immutable lower bank, isolated APK database and
native-qualified switch/rollback cohort. It does not authorize updates to an
arbitrary RAM deployment or mutation of the host APK database. Missing policy
stays off; an existing enabled/disabled policy is preserved. When enabled, the
controller records at most one daily CHECK attempt and uses the same authenticated
plan/apply transaction, resource admission, Stop and rollback ownership rules.

See [RAM update controller](RAM-UPDATE-CONTROLLER.md),
[Core updates](core-updates.md), [RAM bootstrap](RAM-BOOTSTRAP.md) and
[prerequisites](RAM-PREREQUISITES.md). Engine `--ram` storage and native bootstrap
are distinct. Persistent enrollment remains disabled, cold-boot recovery is not
qualified and custom ELF library-path admission remains unresolved.

The boot loader must verify the pinned release checksums and native APK signatures before reconstruction, validate existing state, enforce RAM headroom, and switch consumers as one owned operation with rollback. A missing layer is not an installed current release.

This mode is under local qualification. No release acceptance or reboot proof is implied.
