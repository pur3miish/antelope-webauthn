import antelopeWebAuthnPublicKey from "./_utils/webauthn-public-key.js";

/**
 * Antelope based web authn public key, (browser only)
 * @param {Object} Arg Argument
 * @param {Uint8Array} id
 * @param {String} email User email address or username
 * @param {String} displayName Users display name
 * @param {String} relayingParty The website url to be signed from.
 * @param {Uin8Array} challenge random challenge.
 * @returns {Object} Antelope public key, credential ID and spki public key for used for verification.
 */

interface createWebAuthnKeyArgs {
  id: Uint8Array;
  email: string;
  displayName: string;
  /**
   * Website URL where the signing will be done.
   */
  relayingParty: string;
  challenge: Uint8Array;
}
export default async function createWebAuthnKey({
  id = new Uint8Array(16),
  email,
  displayName,
  relayingParty,
  challenge,
}: createWebAuthnKeyArgs) {
  if (!navigator?.credentials?.create)
    throw new Error("Browser does not support webauthn.");

  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: relayingParty, name: relayingParty },
      user: { id, name: email, displayName },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      attestation: "direct",
      timeout: 6e4,
      challenge: challenge.buffer,
    },
  } as CredentialCreationOptions)) as PublicKeyCredential;

  const response = cred.response as AuthenticatorAttestationResponse;
  const antelope_public_key = await antelopeWebAuthnPublicKey(response);

  return { public_key: antelope_public_key, credential_id: cred.id };
}
