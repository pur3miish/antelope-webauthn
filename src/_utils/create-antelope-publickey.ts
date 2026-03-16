import binary_to_base58 from "base58-js/binary_to_base58.js";
import ripemd160 from "ripemd160-js/ripemd160.js";

import decodeCBOR from "./cbor-decode.js";

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
export default async function createAntelopeWebAuthnPublicKey({
  attestationObject,
  clientDataJSON,
}: AuthenticatorAttestationResponse): Promise<string> {
  const { authData } = decodeCBOR(attestationObject);

  const clientData = JSON.parse(
    new Uint8Array(clientDataJSON).reduce(
      (acc, i) => (acc += String.fromCharCode(i)),
      ""
    )
  );

  const rpid = new URL(clientData.origin).hostname;
  const rpid_hash = authData.slice(0, 32);

  const ripid_chars: number[] = [];
  for (let i = 0; i < rpid.length; i++) ripid_chars.push(rpid[i].charCodeAt(0));

  const check_hash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", Uint8Array.from(ripid_chars))
  );

  new Uint8Array(check_hash).forEach((i, x) => {
    if (i != rpid_hash[x]) throw new Error("Invalid rpid hash");
  });

  const CredIDLenBuffer = new Uint16Array(authData.slice(53, 55));
  const credIDLen = (CredIDLenBuffer[0] << 8) | CredIDLenBuffer[1]; // readUInt16BE
  const COSEPublicKey = authData.slice(55 + credIDLen, authData.length);
  const public_key = decodeCBOR(new Uint8Array(COSEPublicKey).buffer);
  const x = public_key[-2];
  const prefix = public_key[-3].slice(-1) & 1 ? 3 : 2;

  const webauthn_public_key = [
    prefix,
    ...x,
    2,
    ripid_chars.length,
    ...ripid_chars,
  ];

  const checksum = await ripemd160(
    Uint8Array.from([...webauthn_public_key, 87, 65]) // 87, 65 -> WA ascii
  );

  const antelope_public_key =
    "PUB_WA_" +
    binary_to_base58(
      Uint8Array.from([...webauthn_public_key, ...checksum.slice(0, 4)])
    );

  return antelope_public_key;
}
