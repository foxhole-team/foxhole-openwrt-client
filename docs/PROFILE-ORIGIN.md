# Router profile origin

Paired `client.get` adds `export.appMetadata` only for an inbound router
client. Paired `phone.provision` adds the same object beside `profileUri`
when a remote client profile is available:

```json
{
  "schema": 1,
  "kind": "foxhole-openwrt-client",
  "pairingId": "pair-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "clientId": "client-123456abcdef",
  "uriSha256": "<64 lowercase hexadecimal characters>"
}
```

The digest covers the exact UTF-8 URI before app name adaptation.
The URI is bounded to 16384 bytes; metadata has five fixed fields and
fits within 256 JSON bytes. It contains only opaque pairing/client IDs,
version, kind and digest. No address, PIN, token, verifier or key is added.

The router revalidates pairing at the reply boundary. Existing URI,
config and QR representations remain unchanged. Web/QR exports and
ordinary upstream/provider copies stay unmarked.

Metadata is a hint, not a signature or authorization grant. Apps assign
trusted origin locally only after authenticated export over the already
pinned paired-router channel, matching the saved pairing and URI digest.
Provider/file/QR marker text cannot establish that trust. The local record
also binds the stored app profile and configuration digest.

Automatic probing additionally requires current matching pairing,
explicit management opt-in and that profile's actual VPN connection.
The app permits one bounded VPN-network probe per generation and clears
its result on relevant identity changes. Re-pairing remains an explicit
owner action through the existing protected workflow; no certificate pin
or pairing record is silently replaced.

`node --test tests/profile-origin.test.mjs` checks extracted response
functions with bounded host fixtures. `node tests/run-profile-origin.mjs`
compiles the RPC and checks the metadata function in the existing
read-only ucode test container. Neither establishes router/tunnel runtime
acceptance.
