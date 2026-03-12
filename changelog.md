# Antelope webauthn changelog

## v.3.0.0

### Major - 2026-03-12

### Changed

- Updated `createWebAuthnKey` to accept the native `CredentialCreationOptions` object directly.
- This aligns the API with the WebAuthn specification and allows developers full control over credential creation parameters such as authenticator selection, resident key preferences, and attestation configuration.
- The library no longer constructs credential creation options internally.

### Added

- Added `antelope_public_key` to the returned credential object.
- The function now returns:

## v.2.0.0

### Major

- BREAKING: WebAuthn credentials now use `name` (device label) instead of `email` to identify/create keys.
  - This provides better clarity when multiple devices are registered.
  - `email` identifier will no longer be argument to create new keys with.
  - Users must re-register their keys using the new flow.

## v.1.0.0

- stable release

## v.1.0.0-rc.5

- Bug fixed for sha256 so that it can work in node js context.

## v.1.0.0-rc.4

- Typeo fixed for exports and files to include for verify_wa_signature.

## v.1.0.0-rc.2

- Redeployed.

## v.1.0.0-rc.1

## Minor

- Added verify signature

### Patch

- Fixed type in create webauth-signature
- readme updates.

## v.1.0.0-rc

- Initial release
