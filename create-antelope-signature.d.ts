/**
 * Creates an Antelope compatible signature from a webauthn assertion response.
 * The signature can then be verified on chain using the public key associated with the credential.
 * @example
 * ```ts
 * const signature = await createAntelopeSignature(
 *   {
 *     authenticatorData: new Uint8Array([...]),
 *     clientDataJSON: new Uint8Array([...]),
 *     signature: new Uint8Array([...]),
 *   },
 *   "PUB_WA_6eRs44BYTJKPrGTCqR5TuMSQbCrZsNdNSXTHNuNitSdTfVQe8JSf89qy7JwxEnFW7"
 * );
 * ```
 * @param param0 - The response from the authenticator after requesting an assertion.
 * @param public_key - The Antelope compatible public key associated with the credential used to sign the assertion.
 * @returns
 */
export default function createAntelopeSignature({ authenticatorData, signature, clientDataJSON, }: AuthenticatorAssertionResponse, public_key: string): Promise<string>;
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
