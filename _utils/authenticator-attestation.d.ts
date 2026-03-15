export type CreateWebAuthnKeyResult = {
    id: string;
    rawId: ArrayBuffer;
    type: PublicKeyCredential["type"];
    response: AuthenticatorAttestationResponse;
    authenticatorAttachment: PublicKeyCredential["authenticatorAttachment"];
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
};
/**
 * Creates a new webauthn credential, its attestation response, and related metadata by calling `navigator.credentials.create` with the provided options.
 */
export default function authenticatorAttestation(options: CredentialCreationOptions): Promise<CreateWebAuthnKeyResult>;
