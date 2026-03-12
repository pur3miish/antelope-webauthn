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
  createWebAuthnKey,
  createWebAuthnSignature,
  verifyWebAuthnSignature,
} from "antelope-webauthn";

// Step 1: Generate a secure random user/device ID (16 bytes)
const userId = crypto.getRandomValues(new Uint8Array(16));

// Step 2: Generate a random challenge (32 bytes)
// In production this should come from your backend
const challenge = crypto.getRandomValues(new Uint8Array(32));

// Step 3: Create a WebAuthn credential
const credential = await createWebAuthnKey({
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
const antelopePublicKey = credential.antelope_public_key;

console.log("Antelope Public Key:", antelopePublicKey);

// Step 4: Sign a 32-byte hash (e.g., an Antelope transaction digest)
const messageHash = new Uint8Array(32).fill(2); // replace with real SHA-256 hash

const signature = await createWebAuthnSignature(credential, messageHash);

// Step 5: Verify the signature
const verified = await verifyWebAuthnSignature(signature, antelopePublicKey);

console.log("Signature verified:", verified);
```
