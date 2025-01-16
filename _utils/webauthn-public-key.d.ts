export default function createAntelopeWebAuthnPublicKey({ attestationObject, clientDataJSON, }: AuthenticatorAttestationResponse): Promise<string>;
