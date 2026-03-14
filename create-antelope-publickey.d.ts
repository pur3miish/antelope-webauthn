/**
 * Creates an Antelope compatible public key from a webauthn attestation response.
 * The public key can then be used to verify signatures on chain.
 * @param attestationResponse - The response from the authenticator after creating a new credential.
 * @returns An Antelope compatible public key string.
 */
export default function createAntelopeWebAuthnPublicKey({ attestationObject, clientDataJSON, }: AuthenticatorAttestationResponse): Promise<string>;
