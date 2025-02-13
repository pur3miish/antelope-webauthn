# Antelope-webauthn

This project demonstrates how [WebAuthn](https://webauthn.guide/) (Web Authentication) can be used to generate public keys and signatures for Antelope-based blockchains. WebAuthn is a web standard that provides a strong authentication mechanism using hardware-backed credentials like biometrics, security keys, or built-in device authenticators.

Antelope-based blockchains, such as EOS, Telos, XRP, and WAX, require digital signatures for transactions. This package enables users to use WebAuthn standard for generating signatures and public keys (PUB_WA and SIG_WA), that leverage the webauthn standard for authenticating state changes such as token transfers on the blockchain.

### Installation

```
$ npm i antelope-webauthn
```

### Importing modules

```js
import CreateWebAuthnSignature from "antelope-webauthn/create_wa_signature.js";
import CreateWebAuthnPublickey from "antelope-webauthn/create_wa_public_key.js";
import VerifyWebAuthSignature from "antelope-webauthn/verify_wa_signature.js";
```

### About

> This package exports three functions

- [create_wa_signature](./create_wa_signature.d.ts)
- [verify_wa_signature](./verify_wa_signature.d.ts)
- [create_wa_public_key](./create_wa_public_key.d.ts)
