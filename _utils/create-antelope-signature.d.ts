/**
 * The fields from an `AuthenticatorAssertionResponse` required to construct an
 * Antelope signature. These are available as properties of the `response`
 * object returned by {@link authenticatorAssertion}.
 */
export interface CreateAntelopeSignatureInput {
    /** Raw authenticator data bytes from the assertion response. */
    authenticatorData: ArrayBuffer | Uint8Array;
    /** DER-encoded ECDSA signature bytes from the assertion response. */
    signature: ArrayBuffer | Uint8Array;
    /** UTF-8 encoded JSON bytes describing the client data from the assertion response. */
    clientDataJSON: ArrayBuffer | Uint8Array;
}
/**
 * Encodes a WebAuthn assertion response as an Antelope `SIG_WA_…` signature
 * string.
 *
 * The function:
 * 1. DER-decodes the raw ECDSA `signature` to extract `r` and `s`.
 * 2. Computes `SHA-256(authenticatorData || SHA-256(clientDataJSON))` — the
 *    signed digest per the WebAuthn spec.
 * 3. Derives the ECDSA recovery ID (`v`) by checking which of the two
 *    candidate public keys matches the provided `antelope_public_key`.
 * 4. Serialises `(v, r, s, authenticatorData, clientDataJSON)` into the
 *    Antelope WebAuthn signature wire format and Base58-encodes it with a
 *    4-byte RIPEMD-160 checksum, prefixed with `SIG_WA_`.
 *
 * For the common end-to-end flow, prefer {@link antelopeSign} which calls this
 * function internally. Use `createAntelopeSignature` directly when you already
 * have a raw `AuthenticatorAssertionResponse` (e.g. from a custom
 * authenticator flow).
 *
 * @param assertionResponse - The fields from an `AuthenticatorAssertionResponse`.
 *   See {@link CreateAntelopeSignatureInput}.
 * @param antelope_public_key - The `PUB_WA_…` public key string that
 *   corresponds to the credential that produced the assertion. This is used
 *   to determine the correct ECDSA recovery ID.
 * @returns A `SIG_WA_…` encoded Antelope signature string.
 * @throws {Error} If neither recovery ID candidate produces a public key
 *   matching `antelope_public_key`.
 *
 * @example
 * ```ts
 * import { createAntelopeSignature } from "antelope-webauthn";
 *
 * const signature = await createAntelopeSignature(
 *   {
 *     authenticatorData: assertionResponse.authenticatorData,
 *     clientDataJSON: assertionResponse.clientDataJSON,
 *     signature: assertionResponse.signature,
 *   },
 *   "PUB_WA_6eRs44BYTJKPrGTCqR5TuMSQbCrZsNdNSXTHNuNitSdTfVQe8JSf89qy7JwxEnFW7"
 * );
 * // signature → "SIG_WA_..."
 * ```
 */
export default function createAntelopeSignature(assertionResponse: CreateAntelopeSignatureInput, antelope_public_key: string): Promise<string>;
interface WaSignatureArgs {
    r: Uint8Array;
    s: Uint8Array;
    v: 0 | 1;
    authenticatorData: Uint8Array | ArrayBuffer;
    clientDataJSON: Uint8Array | ArrayBuffer;
}
/**
 * Serialize signature into an Antelope SIG_WA signature.
 */
export declare function serialize_wa_signature({ r, s, v, authenticatorData, clientDataJSON, }: WaSignatureArgs): Promise<string>;
export {};
