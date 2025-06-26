# Antelope-webauthn

[![npm version](https://img.shields.io/npm/v/antelope-webauthn.svg)](https://www.npmjs.com/package/antelope-webauthn) [![npm downloads](https://img.shields.io/npm/dm/antelope-webauthn.svg)](https://www.npmjs.com/package/antelope-webauthn) [![license](https://img.shields.io/npm/l/antelope-webauthn.svg)](https://github.com/your-repo/antelope-webauthn/blob/main/LICENSE)

A WebAuthn-based crypto utility for generating and verifying signatures on Antelope blockchains (e.g., EOS, WAX, XRP, Telos) using the P-256 curve. It leverages WebAuthn’s secure, hardware-backed authentication to create keys and signatures (PUB_WA and SIG_WA) for signing blockchain transactions.

This project demonstrates how [WebAuthn](https://webauthn.guide/) (Web Authentication) can be used to generate public keys and signatures for Antelope-based blockchains. WebAuthn is a web standard that provides a strong authentication mechanism using hardware-backed credentials like biometrics, security keys, or built-in device authenticators.

## ✨ Features

- 🔐 Non-exportable keys bound to the user’s device.

- 📎 Creates Antelope-compatible public keys (PUB*WA*…) and signatures (SIG*WA*…).

- ✅ Verifies WebAuthn signatures using modern WebCrypto APIs.

- 🧪 Works in modern browsers with WebAuthn support (Chrome, Firefox, Edge, Safari ≥ 18.5).

### Disclaimer

antelope-webauthn is an independent open-source project, not affiliated with any organizations. Use at your own risk.

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
const id = window.crypto.getRandomValues(new Uint8Array(16));

// Step 2: Generate a random challenge (32 bytes)
// This should come from your backend or be a hash of the transaction data
const challenge = window.crypto.getRandomValues(new Uint8Array(32));

// Step 3: Create a WebAuthn public key credential bound to this device
const device_key = await createWebAuthnKey({
  name: "key-name", // Used to identify the user
  displayName: "Example User", // Shown during credential creation
  relayingParty: window.location.hostname, // Your app’s domain
  id, // Unique identifier for the user/device
  challenge, // Challenge to ensure legitimacy
});

// Step 4: Sign a 32-byte hash (e.g., a serialized Antelope transaction hash)
const messageHash = new Uint8Array(32).fill(2); // Replace with a real SHA-256 hash
const signature = await createWebAuthnSignature(device_key, messageHash);

// Step 5: Verify the signature using the device’s public key
const verified = await verifyWebAuthnSignature(
  signature,
  device_key.public_key
);

console.log("Signature verified:", verified);
```
