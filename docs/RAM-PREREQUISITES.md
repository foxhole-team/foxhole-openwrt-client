# RAM recovery enrollment prerequisites

Enrollment checks persistent dependencies before creating the bootstrap directory,
descriptor or enabled init link. `ram-bootstrap-prerequisites.uc` and its pure model
are installation tools only; they are not copied into the bounded boot seed. The
128 KiB seed cap and 512 KiB flash reserve remain unchanged.

The checker compares current protected regular files with the boot view formed by
read-only ROM and a supported persistent overlay. Symlinks are resolved one component
at a time. An absolute link is anchored to the candidate namespace, and candidate
parent links are never followed outside it. A ROM match cannot admit a dependency
currently supplied only by a RAM bind. Missing, writable, mismatched or unsupported
backing fails enrollment with a `RAM_RECOVERY_PREREQUISITE` error.

The closure covers the Ucode interpreter and fs/digest modules, native APK and shell
utilities, procd scripts, ELF interpreters/DT_NEEDED libraries, the stock libustream
TLS plugin and CA certificates. The supplied verified fetch helper is intentionally
allowed as temporary input: only its dependencies must already persist, and the
normal installer checks its digest/architecture before copying it to the seed.

The existing runtime `engine` API determines the provider; enrollment does not change
it or accept a caller's provider claim. The existing qualified legacy Go launcher
must persist. Core slots use the existing registry verification; selected launchers,
slot/producer/capability and legal metadata must persist, while verified RAM payloads
may remain volatile. The checker also requires a persistent TUN module with the
current kernel vermagic, or persistent builtin metadata and current builtin presence.
It installs no kernel module/library, downloads no payload and starts no service.

For a read-only qualification, Root runs the checker with the actual verified helper
path and digest under a clean environment. The checker emits only provider and file
counts; profile/configuration bodies and credentials are not exported. A positive
admission does not claim physical cold-boot execution. Router reboot is prohibited
for the current task, and that scope remains untested.
