/**
 * The normalised result of a successful WebAuthn credential creation.
 * Pass `response` to {@link createAntelopePublicKey} to derive the
 * `PUB_WA_…` key, and store `id` as the `credential_id` in your
 * {@link DeviceKey} record.
 */
export type CreateWebAuthnKeyResult = {
    /** Base64url credential identifier — store this as `DeviceKey.credential_id`. */
    id: string;
    /** Raw binary credential identifier (same value as `id`, unencoded). */
    rawId: ArrayBuffer;
    /** Always `"public-key"` for WebAuthn credentials. */
    type: PublicKeyCredential["type"];
    /**
     * The full attestation response from the authenticator.
     * Pass this to {@link createAntelopePublicKey} to extract the public key.
     */
    response: AuthenticatorAttestationResponse;
    /**
     * Whether the credential is bound to a platform authenticator (`"platform"`)
     * or a roaming authenticator (`"cross-platform"`). `null` when not reported.
     */
    authenticatorAttachment: PublicKeyCredential["authenticatorAttachment"];
    /** Any extension outputs returned by the authenticator. */
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
};
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
export default function authenticatorAttestation(options: CredentialCreationOptions): Promise<CreateWebAuthnKeyResult>;
