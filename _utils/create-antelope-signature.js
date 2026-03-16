import base58_to_binary from "base58-js/base58_to_binary.js";
import binary_to_base58 from "base58-js/binary_to_base58.js";
import varuint32 from "eosio-wasm-js/varuint32.js";
import ripemd160 from "ripemd160-js/ripemd160.js";
import { array_to_number } from "./array_to_number.js";
import calculateRecID from "./calculate_recovery_id.js";
import decodeDER from "./decode-der.js";
import sha256 from "./sha256.js";
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
export default async function createAntelopeSignature(assertionResponse, antelope_public_key) {
    const { authenticatorData, signature, clientDataJSON } = assertionResponse;
    const { r, s } = decodeDER(new Uint8Array(signature));
    const serializeArg = { r, s, clientDataJSON, authenticatorData };
    const public_key_bytes = base58_to_binary(antelope_public_key.replace("PUB_WA_", ""));
    const clientDataHash = await sha256(new Uint8Array(clientDataJSON));
    const hash = await sha256(Uint8Array.from([...new Uint8Array(authenticatorData), ...clientDataHash]));
    const rec_id = calculateRecID(public_key_bytes.slice(0, 33), { r: array_to_number(r), s: array_to_number(s) }, hash);
    return serialize_wa_signature({ v: rec_id, ...serializeArg });
}
/**
 * Serialize signature into an Antelope SIG_WA signature.
 */
export async function serialize_wa_signature({ r, s, v, authenticatorData, clientDataJSON, }) {
    const sig = Uint8Array.from([
        v + 27 + 4,
        ...r,
        ...s,
        // @ts-expect-error - I want to check this
        ...varuint32(authenticatorData.length ?? authenticatorData.byteLength)
            .match(/[a-z0-9]{2}/gmu)
            .map((i) => Number(`0x${i}`)),
        ...new Uint8Array(authenticatorData),
        // @ts-expect-error - I want to check this
        ...varuint32(clientDataJSON.length ?? clientDataJSON.byteLength)
            .match(/[a-z0-9]{2}/gmu)
            .map((i) => Number(`0x${i}`)),
        ...new Uint8Array(clientDataJSON),
    ]);
    const WA = [87, 65];
    const checksum = await (await ripemd160(Uint8Array.from([...sig, ...WA]))).slice(0, 4);
    return ("SIG_WA_" +
        binary_to_base58(Uint8Array.from([...sig, ...checksum])));
}
