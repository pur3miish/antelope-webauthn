export type CreateWebAuthnKeyResult = {
    id: string;
    rawId: ArrayBuffer;
    type: PublicKeyCredential["type"];
    response: AuthenticatorAttestationResponse;
    authenticatorAttachment: PublicKeyCredential["authenticatorAttachment"];
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
    antelope_public_key: string;
};
/**
 * creates a new webauthn credential and returns an Antelope compatible public key along with the attestation response and other relevant information.
 * @param options
 * @returns
 */
export default function authenticatorAttestation(options: CredentialCreationOptions): Promise<CreateWebAuthnKeyResult>;
