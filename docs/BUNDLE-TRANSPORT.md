# Native bundle transport

The compact installer can obtain upstream dependency APKs from `native-install.tar`.
Small planning metadata, trust keys, signed indexes, BASE and protocol module APKs,
and RAM runtime binaries remain direct assets. Module updates retain their existing
signed package and index paths.

`bundle-transport.json` uses schema 1:

```json
{"schema":1,"archive":{"file":"native-install.tar","sha256":"<actual SHA-256>","bytes":0},"entries":{"<logical filename>":{"sha256":"<actual SHA-256>","bytes":0}}}
```

The example is a schema illustration, not an admissible release descriptor. The
actual descriptor contains positive archive bytes and actual artifact digests.
The descriptor and archive are bound by the trusted top-level `SHA256SUMS`.
Every archived logical filename also retains its digest in that manifest. The
producer writes sorted compact JSON with one final newline; the router checks
those canonical bytes to exclude duplicate or escaped JSON keys.

The archive is plain USTAR, not gzip. Each member name is `f-` followed by the
SHA-256 of the ASCII logical filename. Members are regular files with mode 0644,
UID/GID and timestamp zero, empty owner names, link name and prefix, and zero
padding. Normal Python USTAR writes empty device-number fields for these regular
files. Directories, links, PAX/GNU extensions, duplicate or unknown members, bad
checksums, nonzero content padding and nonzero trailing data are rejected. Two
zero end records are required; further zero padding is bounded to 10 KiB.

Hard limits are 512 MiB per archive, 1,024 members, 128 MiB per member and 2 GiB
of declared content. These limits do not establish that any router can stage the
whole bundle. The existing selected-package planner runs before archive download
with available RAM reduced by the full archive size, descriptor size and an
additional conservative 16 MiB transport allowance. This is a budgeting policy,
not a measured minimum-RAM claim.

The router verifies the entire archive digest before parsing members, then streams
at most 64 KiB at a time and checks every member digest, including unselected
members. It materializes selected files only and removes the archive afterward.
The existing APK/index signature, package identity, ABI, payload and transaction
checks still apply. Existing FoxHole state still requires paired management.

The producer runs after normal signed-artifact flat-bundle validation:

```sh
python3 tools/build-bundle-transport.py --bundle "$VERIFIED_FLAT_BUNDLE" \
  --manifest-sha256 "$ACTUAL_FLAT_MANIFEST_SHA256" --output "$NEW_TRANSPORT"
```

It archives only dependency files named `apk-<SHA-256>.apk`, preserves all inner
bytes, and rejects a transport output with 200 or more files. Final publication
must also count any added source/signature assets. The new outer manifest must
be signed and verified after transport assembly. A downloader which understands
only flat URLs must first materialize this transport; logical archive entries
are not independent release-asset URLs.
