import assertBrowserCompatibility from "./browser-compatability.js";
/**
 * Wraps `navigator.credentials.create` to register a new WebAuthn credential
 * and returns a normalised {@link CreateWebAuthnKeyResult}.
 *
 * Use the returned `response` with {@link createAntelopePublicKey} to derive
 * the `PUB_WA_…` public key for your Antelope account, and store `id` as the
 * `credential_id` in your {@link DeviceKey} record.
 *
 * @param options - Standard `CredentialCreationOptions` passed directly to
 *   `navigator.credentials.create`.
 * @returns A normalised {@link CreateWebAuthnKeyResult} containing the new
 *   credential's ID, attestation response, and metadata.
 * @throws {Error} If the browser does not support the WebAuthn API.
 * @throws {Error} If `navigator.credentials.create` returns `null` (e.g. the
 *   user cancelled the registration gesture).
 * @throws {DOMException} If the authenticator returns a WebAuthn error.
 *
 * @example
 * ```ts
 * import { authenticatorAttestation, createAntelopePublicKey } from "antelope-webauthn";
 *
 * const result = await authenticatorAttestation({
 *   publicKey: {
 *     challenge: crypto.getRandomValues(new Uint8Array(32)),
 *     rp: { name: "My App", id: "example.com" },
 *     user: { id: new Uint8Array(16), name: "alice", displayName: "Alice" },
 *     pubKeyCredParams: [{ type: "public-key", alg: -7 }],
 *   },
 * });
 *
 * const publicKey = await createAntelopePublicKey(result.response);
 * // publicKey → "PUB_WA_..."
 * // Store result.id as credential_id alongside publicKey.
 * ```
 */
export default async function authenticatorAttestation(options) {
    assertBrowserCompatibility();
    const cred = (await navigator.credentials.create(options));
    if (!cred) {
        throw new Error("Failed to create WebAuthn credential.");
    }
    const response = cred.response;
    return {
        id: cred.id,
        rawId: cred.rawId,
        type: cred.type,
        response,
        authenticatorAttachment: cred.authenticatorAttachment ?? null,
        clientExtensionResults: cred.getClientExtensionResults(),
    };
}
