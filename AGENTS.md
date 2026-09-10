# FoxHole OpenWrt client

- Keep this public tree independent of operational configurations.
- Never add real deployments, keys, QR exports, certificates or backups.
  Reserved test networks and `.invalid` placeholders are permitted.
  The original dashboard screenshot is retained at the owner's request.
- Preserve the existing Hysteria engine, LuCI ACLs and routing semantics.
- Default installation uses flash; RAM requires the explicit `--ram` flag.
- UI translations belong in the existing English and Russian locale files.
- Keep comments in English, concise and limited to non-obvious invariants.
- Run `npm run check`, installer tests and reproducible source builds.
- Do not access a physical router, sign, tag, push or publish without an
  explicit request. Document untested device/release gates accurately.
