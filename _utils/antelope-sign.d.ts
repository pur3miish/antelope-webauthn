/**
 * A registered WebAuthn device key associated with an Antelope account.
 * Obtain these values when the credential was first created via {@link authenticatorAttestation}
 * and {@link createAntelopePublicKey}.
 */
export type DeviceKey = {
    /** Antelope-formatted public key string, e.g. `"PUB_WA_..."`. */
    public_key: string;
    /** Base64url credential ID returned by the WebAuthn API at registration time. */
    credential_id: string;
};
/**
 * Prompts the user's authenticator to sign a challenge and returns an
 * Antelope-compatible `SIG_WA_…` signature string.
 *
 * Internally this calls {@link authenticatorAssertion} to obtain a WebAuthn
 * assertion and then encodes it as an Antelope WebAuthn signature via
 * {@link createAntelopeSignature}.
 *
 * @param device_keys - One or more registered {@link DeviceKey} objects that
 *   are allowed to satisfy the assertion. The authenticator will pick whichever
 *   credential it holds.
 * @param hash - The 32-byte transaction digest (challenge) to sign. Accepts
 *   either a raw `Uint8Array` or a lowercase hex string.
 * @returns A `SIG_WA_…` encoded Antelope signature string.
 * @throws {Error} If the browser does not support the WebAuthn API.
 * @throws {Error} If none of the provided `device_keys` match the credential
 *   selected by the authenticator.
 *
 * @example
 * ```ts
 * import { antelopeSign } from "antelope-webauthn";
 *
 * const signature = await antelopeSign(
 *   [{ public_key: "PUB_WA_...", credential_id: "base64url-id" }],
 *   "a3f1...hex-transaction-hash"
 * );
 * // signature → "SIG_WA_..."
 * ```
 */
export default function antelopeSign(device_keys: DeviceKey[], hash: Uint8Array | string): Promise<string>;
