# RAM deployment

This installer prepares signed release APKs in a separate RAM package root. The host APK database, owner profiles, pairing, TLS identities and installed Hysteria module remain separate. Activation exposes only reviewed public paths; it never mounts a package database or private configuration directory.

A root-owned active receipt distinguishes this deployment from a flash package upgrade. Package and engine mutations are refused while RAM deployment is active, including automatic updates. Native host APK queries continue to report the retained rollback package.

The boot loader must verify the pinned release checksums and native APK signatures before reconstruction, validate existing state, enforce RAM headroom, and switch consumers as one owned operation with rollback. A missing layer is not an installed current release.

This mode is under local qualification. No release acceptance or reboot proof is implied.
