![relockeql logo](/src/relocke-webauthn.svg)

# antelope-webauthn

[![npm version](https://img.shields.io/npm/v/antelope-webauthn.svg)](https://www.npmjs.com/package/antelope-webauthn) [![npm downloads](https://img.shields.io/npm/dm/antelope-webauthn.svg)](https://www.npmjs.com/package/antelope-webauthn) [![license](https://img.shields.io/npm/l/antelope-webauthn.svg)](https://github.com/your-repo/antelope-webauthn/blob/main/LICENSE)

`antelope-webauthn` demonstrates how the **WebAuthn authentication standard** can be used to generate and use **hardware-backed cryptographic keys** for signing transactions on **Antelope-based blockchains**.

Supported ecosystems include networks built on the Antelope architecture such as:

- WAX
- Telos
- FIO
- XPR Network
- Vaulta
- Other Antelope-based DPoS chains

Antelope blockchains use **public/private key cryptography** to authorize transactions. Traditionally these keys are generated and stored in software wallets, browser extensions, mobile wallets, or dedicated hardware wallets.

This project takes a different approach by using **WebAuthn authenticators** to generate and protect the signing key material.

This provides several important properties:

- **Hardware-backed security** through platform authenticators and security keys
- **Non-exportable private keys** that remain protected by the authenticator
- **Biometric authorization** through Touch ID, Face ID, Windows Hello, and Android biometrics
- **Support for external security keys** such as YubiKeys
- Optional **passkey-style synchronization** where supported by the credential manager
- A path to using modern device security models for Antelope transaction signing

The library converts WebAuthn-generated key material into **Antelope-compatible key formats**:

- `PUB_WA_*` public keys
- `SIG_WA_*` signatures

These formats allow WebAuthn credentials to be used directly in Antelope-based signing workflows.

## Installation

```
$ npm i antelope-webauthn
```

## 🛠 Requirements

- Node.js ≥ 18
- Modern browser with WebAuthn support
- Supports only ES Modules (no CommonJS)

### Browser Compatibility

This package checks for minimum supported versions of modern browsers:

| Browser        | Minimum Version |
| -------------- | --------------- |
| Safari (macOS) | 18.5            |
| Safari (iOS)   | 16              |
| Chrome         | 113             |
| Firefox        | 110             |
| Edge           | 113             |

## 🚀 Example Usage

```js
import {
  authenticatorAttestation,
  createAntelopePublicKey,
  antelopeSign,
  verifyWebAuthnSignature,
} from "antelope-webauthn";

// Step 1: Generate a secure random user/device ID (16 bytes)
const userId = crypto.getRandomValues(new Uint8Array(16));

// Step 2: Generate a random challenge (32 bytes)
// In production this should come from your backend
const challenge = crypto.getRandomValues(new Uint8Array(32));

// Step 3: Create a WebAuthn credential
const credential = await authenticatorAttestation({
  publicKey: {
    rp: {
      name: "Example App",
      id: window.location.hostname,
    },

    user: {
      id: userId,
      name: "user@example.com",
      displayName: "Example User",
    },

    challenge,

    pubKeyCredParams: [
      { type: "public-key", alg: -7 }, // ES256 / P-256
    ],

    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },

    timeout: 60000,
    attestation: "none",
  },
});

// The returned credential contains the Antelope public key
const antelopePublicKey = await createAntelopePublicKey(credential.response);

console.log("Antelope Public Key:", antelopePublicKey);

// Step 4: Sign a 32-byte hash (e.g., an Antelope transaction digest)
const messageHash = new Uint8Array(32).fill(2); // replace with real SHA-256 hash

// Generate antelope signature
const signature = await antelopeSign(
  [{ public_key: antelopePublicKey, credential_id: credential.id }],
  messageHash
);

// Step 5: Verify the signature
const verified = await verifyWebAuthnSignature(signature, antelopePublicKey);

console.log("Signature verified:", verified);
```

## API Reference

### `authenticatorAttestation(options)`

Registers a new WebAuthn credential by calling `navigator.credentials.create`. Use this during account setup to generate a hardware-backed key pair.

**Parameters**

- `options: CredentialCreationOptions` — Standard WebAuthn credential creation options (rp, user, challenge, pubKeyCredParams, etc.)

**Returns** `Promise<CreateWebAuthnKeyResult>` — An object containing:

- `id: string` — Base64url-encoded credential ID
- `rawId: ArrayBuffer`
- `type: string`
- `response: AuthenticatorAttestationResponse` — Pass this to `createAntelopePublicKey`
- `authenticatorAttachment: string | null`
- `clientExtensionResults: AuthenticationExtensionsClientOutputs`

---

### `createAntelopePublicKey(response)`

Derives an Antelope-compatible `PUB_WA_*` public key from a WebAuthn attestation response. Store this key on-chain to authorize future signatures from this credential.

**Parameters**

- `response: AuthenticatorAttestationResponse` — The `response` field from `authenticatorAttestation`

**Returns** `Promise<string>` — An Antelope public key string in `PUB_WA_` format.

---

### `antelopeSign(device_keys, hash)`

Signs a 32-byte hash (e.g. an Antelope transaction digest) using a previously registered WebAuthn credential. Triggers a biometric/PIN prompt on the user's device.

**Parameters**

- `device_keys: { public_key: string, credential_id: string }[]` — One or more registered credentials to offer the authenticator. The first one the device accepts will be used.
- `hash: Uint8Array | string` — The 32-byte message hash to sign. Accepts a `Uint8Array` or a hex string.

**Returns** `Promise<string>` — An Antelope signature string in `SIG_WA_` format.

---

### `verifyAntelopeSignature(signature, public_key)`

Verifies a `SIG_WA_*` signature against a `PUB_WA_*` public key on the client or server side using the Web Crypto API.

**Parameters**

- `signature: string` — An Antelope signature in `SIG_WA_` format, as returned by `antelopeSign`
- `public_key: string` — The `PUB_WA_` public key associated with the signing credential

**Returns** `Promise<boolean>` — `true` if the signature is valid.

---

### `authenticatorAssertion(options)`

Low-level wrapper around `navigator.credentials.get`. Used internally by `antelopeSign`. Exposed for advanced use cases where you need direct access to the raw `PublicKeyCredential` assertion response before Antelope serialization.

**Parameters**

- `options: CredentialRequestOptions` — Standard WebAuthn credential request options

**Returns** `Promise<PublicKeyCredential>`

---

### `createAntelopeSignature(response, public_key)`

Low-level function that converts a raw WebAuthn assertion response into a `SIG_WA_*` signature string. Used internally by `antelopeSign`. Exposed for advanced use cases where you already have an `AuthenticatorAssertionResponse`.

**Parameters**

- `response: AuthenticatorAssertionResponse` — The assertion response from `authenticatorAssertion`
- `public_key: string` — The `PUB_WA_` public key for the signing credential

**Returns** `Promise<string>` — An Antelope signature string in `SIG_WA_` format.

---

### `classifyWebAuthnCredential(input)`

Inspects a WebAuthn authenticator data response and classifies the credential type. Useful for UX decisions (e.g. warning users that a synced passkey is less secure than a hardware key for on-chain authorization).

**Parameters**

- `input.response` — An object with `authenticatorData: ArrayBuffer` (from an assertion or attestation response)
- `input.authenticatorAttachment?: "platform" | "cross-platform" | null` — Usually `PublicKeyCredential.authenticatorAttachment`
- `input.transports?: string[] | null` — Optional transport hints stored at registration time

**Returns** `CredentialClassification`:

- `kind: "hardware-security-key" | "device-bound" | "synced-passkey" | "unknown"`
- `confidence: "high" | "medium" | "low"`
- `reason: string` — Human-readable explanation of the classification
- `flags` — Parsed authenticator data flags: `userPresent`, `userVerified`, `backupEligible`, `backupState`, `attestedCredentialData`, `extensionsIncluded`, `signCount`
