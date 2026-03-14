export type CreateWebAuthnKeyResult = {
    id: string;
    rawId: ArrayBuffer;
    type: PublicKeyCredential["type"];
    response: AuthenticatorAttestationResponse;
    authenticatorAttachment: PublicKeyCredential["authenticatorAttachment"];
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
    antelope_public_key: string;
};
export default function createWebAuthnKey(options: CredentialCreationOptions): Promise<CreateWebAuthnKeyResult>;
