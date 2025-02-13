import antelopeWebAuthnPublicKey from "./_utils/webauthn-public-key.js";

export type createWebAuthnKeyArgs = {
  /**
   * the ID for the PublicKeyCredentialUserEntity.
   */
  id: Uint8Array;
  /**
   * User email address or username
   */
  email: string;
  /**
   * Users display name
   */
  displayName: string;
  /**
   * Website URL where the signing will be done.
   */
  relayingParty: string;
  /**
   * Challenge to be signed.
   */
  challenge: Uint8Array;
};

export type device_key = {
  id: Uint8Array;
  public_key: string;
  credential_id: string;
};

export default async function createWebAuthnKey({
  id = crypto.getRandomValues(new Uint8Array(16)),
  email,
  displayName,
  relayingParty,
  challenge,
}: createWebAuthnKeyArgs): Promise<device_key> {
  if (!navigator?.credentials?.create)
    throw new Error("Browser does not support webauthn.");

  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: relayingParty, name: relayingParty },
      user: { id, name: email, displayName } as PublicKeyCredentialUserEntity,
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

  return { public_key: antelope_public_key, credential_id: cred.id, id };
}
