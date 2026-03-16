/**
 * Derives an Antelope `PUB_WA_…` public key from a WebAuthn attestation
 * response produced during credential registration.
 *
 * The function:
 * 1. CBOR-decodes the `attestationObject` to extract the authenticator data.
 * 2. Verifies the RP ID hash against the `origin` in `clientDataJSON`.
 * 3. Reads the COSE-encoded P-256 public key from the credential data.
 * 4. Encodes it in the Antelope WebAuthn public key format with a RIPEMD-160
 *    checksum and Base58 encoding, prefixed with `PUB_WA_`.
 *
 * Store the returned string alongside the credential ID as a {@link DeviceKey}
 * so it can later be passed to {@link antelopeSign} and used on-chain.
 *
 * @param attestationResponse - The `AuthenticatorAttestationResponse` returned
 *   by {@link authenticatorAttestation} (or directly from
 *   `navigator.credentials.create`).
 * @returns A `PUB_WA_…` Antelope public key string.
 * @throws {Error} If the RP ID hash in the authenticator data does not match
 *   the origin in `clientDataJSON` (tampered or mismatched response).
 *
 * @example
 * ```ts
 * import { authenticatorAttestation, createAntelopePublicKey } from "antelope-webauthn";
 *
 * const { id, response } = await authenticatorAttestation({ publicKey: { ... } });
 * const publicKey = await createAntelopePublicKey(response);
 * // publicKey → "PUB_WA_6eRs44BYTJKPrGTCqR5T..."
 *
 * // Persist these two values together as a DeviceKey:
 * const deviceKey = { credential_id: id, public_key: publicKey };
 * ```
 */
export default function createAntelopeWebAuthnPublicKey({ attestationObject, clientDataJSON, }: AuthenticatorAttestationResponse): Promise<string>;
