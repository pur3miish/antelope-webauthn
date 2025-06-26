# Antelope webauthn changelog

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
