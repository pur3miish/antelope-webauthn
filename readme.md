# Antelope-webauthn

This project demonstrates how WebAuthn (Web Authentication) can be used to generate public keys and signatures for Antelope-based blockchains. WebAuthn is a web standard that provides a strong authentication mechanism using hardware-backed credentials like biometrics, security keys, or built-in device authenticators.

Antelope-based blockchains, such as EOS, Telos, and WAX, require digital signatures for transactions. This package enables users to use WebAuthn standard for generating signatures and public keys (PUB_WA and SIG_WA), that provided end to end cryptography.

### Installation

```
$ npm i antelope-webauthn
```

### Import

```js
import createWebAuthnSignature from "antelope-webauthn/create_wa_signature.js";
import createWebAuthnPublickey from "antelope-webauthn/create_wa_public_key.js";
```
