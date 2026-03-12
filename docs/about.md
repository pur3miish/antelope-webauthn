# About antelope-webauthn

## Why This Package Exists

WebAuthn was designed for authentication on the web, not specifically for blockchain signing. However, WebAuthn authenticators generate and protect strong asymmetric keypairs and can produce signatures over challenge data.

`antelope-webauthn` bridges that capability into the Antelope ecosystem.

The package allows developers to:

- Create a WebAuthn credential using the browser's native WebAuthn API
- Extract and derive an Antelope-compatible public key from the credential attestation
- Use the authenticator to sign a digest
- Convert the resulting signature into an Antelope-compatible signature format
- Verify those signatures using modern WebCrypto APIs

This makes it possible to build Antelope applications that use:

- platform authenticators
- hardware security keys
- passkeys

as secure signing primitives for blockchain transactions.

---

## How This Project Uses WebAuthn

At a high level, the flow works like this:

1. Your application calls `createWebAuthnKey(...)` with standard WebAuthn credential creation options.
2. The browser invokes `navigator.credentials.create(...)`.
3. A WebAuthn authenticator generates a **P-256 keypair**.
4. The authenticator returns a `PublicKeyCredential`.
5. `antelope-webauthn` parses the attestation response and derives an **Antelope-compatible public key**.
6. The returned credential is preserved, but an additional `antelope_public_key` property is attached.
7. That credential can later be used to sign a challenge or digest, producing an Antelope-compatible `SIG_WA_*` signature.

This means the package does **not replace WebAuthn**. It builds on top of it and adapts the resulting credential material into something Antelope applications can use.

---

## WebAuthn Authenticators, Passkeys, and Credential Storage

WebAuthn credentials are created and stored by an **authenticator**, which is a hardware or OS-level security component responsible for generating and protecting the private key.

Authenticators can be built into a device, such as:

- **Touch ID**
- **Face ID**
- **Android biometrics**
- **Windows Hello**

They can also exist as **external security keys**, such as:

- **YubiKey**
- **FIDO2 security keys**
- other USB, NFC, or Bluetooth authenticators

When a credential is created, the authenticator generates a **public/private key pair** and returns the **public key** to the relying party application.

The **private key never leaves the authenticator**.

This is one of the most important security properties of WebAuthn and one of the main reasons it is useful for blockchain applications.

---

## Where WebAuthn Stops

The WebAuthn specification defines:

- how credentials are created
- how authentication challenges are signed
- the structure of authenticator data
- the flags that describe credential capabilities and state

However, **WebAuthn does not define how credentials are stored or synchronized across devices**.

That responsibility belongs to the **platform credential manager**, which is implemented by the operating system, browser ecosystem, or password manager.

Examples include:

- **Apple iCloud Keychain**
- **Google Password Manager**
- **Microsoft Windows credential infrastructure**
- **1Password**
- **Bitwarden**
- **Dashlane**

These systems may store credentials locally or securely synchronize them across a user's trusted devices.

When synchronization occurs, the credential is commonly referred to as a **passkey**.

---

## Device-Bound Credentials vs Multi-Device Passkeys

The WebAuthn ecosystem distinguishes between credentials that are intended to remain local to a device and credentials that are capable of being backed up or synchronized.

### Device-Bound Credential

A device-bound credential exists **only on the device where it was created**.

The private key is protected by secure hardware or a trusted platform component such as:

- Apple **Secure Enclave**
- Windows **TPM**
- Android **Keystore**

These credentials are generally **not intended to be synchronized**.

For blockchain applications, device-bound credentials can be attractive because they behave more like traditional hardware-wallet security models.

### Multi-Device Credential (Passkey)

A multi-device credential is capable of being **securely backed up or synchronized** through a credential manager.

The private key material remains protected by platform security mechanisms, but the credential can be replicated across a user’s trusted devices in a way controlled by the platform or credential manager.

These are commonly referred to as **passkeys**.

For blockchain applications, this can improve usability and recovery across devices, though the trust model differs from a strictly device-bound credential.

---

## Platform Examples

| Platform | Credential Manager | Typical Behavior |
| --- | --- | --- |
| iOS / macOS | iCloud Keychain | Passkeys can sync across Apple devices |
| Android / Chrome | Google Password Manager | Passkeys can sync across Google-managed devices |
| Windows | Windows Hello | Often device-bound, but depends on platform behavior |
| Password managers | Bitwarden, 1Password, Dashlane | May sync passkeys across vault-connected devices |

The exact behavior depends on:

- platform implementation
- browser behavior
- authenticator capabilities
- user settings
- credential manager support

---

## Detecting Credential Type

WebAuthn exposes two flags in the `authenticatorData` structure that help indicate whether a credential is capable of being backed up.

| Flag | Name            | Meaning                                         |
| ---- | --------------- | ----------------------------------------------- |
| BE   | Backup Eligible | Credential **can be backed up or synchronized** |
| BS   | Backup State    | Credential **is currently backed up**           |

### Interpretation

| BE  | BS  | Meaning                                           |
| --- | --- | ------------------------------------------------- |
| 0   | 0   | Device-bound credential                           |
| 1   | 0   | Backup-eligible credential that may support sync  |
| 1   | 1   | Credential reports that it is backed up or synced |

### Important Notes

- **BE indicates capability**, not certainty that the credential has been synchronized.
- **BS indicates the authenticator reports a backup exists**, but does not reveal where or by whom it is managed.
- WebAuthn intentionally **does not expose the credential manager provider** such as iCloud, Google Password Manager, or Bitwarden.
- This limitation is intentional and helps prevent fingerprinting and preserve user privacy.

---

## Credential Storage Architecture

A typical WebAuthn credential flow involves multiple layers:

### 1. User Device

The physical device being used, such as a phone, laptop, tablet, or desktop.

### 2. Browser or Application

The browser or app invoking the WebAuthn APIs.

### 3. Authenticator

The component that generates and protects the private key.

Examples include:

- Secure Enclave
- TPM
- Android Keystore
- external FIDO2 security key

### 4. Credential Manager

An optional synchronization or backup layer that may store eligible credentials across trusted devices.

Examples include:

- iCloud Keychain
- Google Password Manager
- 1Password
- Bitwarden

### 5. Relying Party Server

The application backend that stores the **public key** and verifies signatures. It never receives the private key.

### Example on Apple Devices

On Apple platforms, a common model is:

- the browser or application invokes WebAuthn
- the **Secure Enclave** acts as the authenticator
- **iCloud Keychain** may act as the synchronization layer for eligible credentials
- the application server stores only the **public key**

The private key remains protected by the platform authenticator.

---

## How WebAuthn Maps to Antelope Keys and Signatures

Antelope chains expect blockchain-compatible public keys and signatures. WebAuthn, by contrast, returns web authentication structures such as:

- `PublicKeyCredential`
- `AuthenticatorAttestationResponse`
- `AuthenticatorAssertionResponse`
- `clientDataJSON`
- `authenticatorData`
- DER-encoded or authenticator-produced signature material

`antelope-webauthn` adapts that material into Antelope-compatible forms.

### Public Key Mapping

When a credential is created, the authenticator generates a **P-256 keypair**.

The attestation response contains public key material that can be parsed and transformed into an Antelope-compatible public key string:

- WebAuthn native result: credential + attestation response
- Package output: `antelope_public_key`
- Antelope representation: `PUB_WA_*`

This lets the application store and use the credential in a blockchain-oriented way without losing the original WebAuthn credential object.

### Signature Mapping

When signing, the authenticator signs challenge-related data using the private key it protects.

`antelope-webauthn` uses that signature flow and converts the resulting data into an Antelope-compatible signature string:

- WebAuthn native result: authenticator assertion + signature bytes
- Package output: Antelope signature string
- Antelope representation: `SIG_WA_*`

This allows transaction digests or similar signing payloads to be verified and transported using conventions that fit the Antelope ecosystem.

---

## Why P-256 Matters

WebAuthn authenticators commonly support **ES256**, which uses the **P-256 elliptic curve**.

This is important because the package uses that curve to derive and encode Antelope-compatible key material.

In practical terms:

- the authenticator generates a **P-256 keypair**
- the package extracts the public component
- the package converts it into `PUB_WA_*`
- signatures produced by the authenticator are adapted into `SIG_WA_*`

This makes WebAuthn a viable cryptographic primitive for Antelope-compatible signing workflows.

---

## What the Package Returns

The updated credential creation API accepts native WebAuthn options and returns the original `PublicKeyCredential` with an additional Antelope-specific property.

### Function Signature

```ts
createWebAuthnKey(
  options: CredentialCreationOptions
): Promise<PublicKeyCredential & { antelope_public_key: string }>
```
