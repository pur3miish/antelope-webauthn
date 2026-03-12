export default function createWebAuthnKey(options: CredentialCreationOptions): Promise<PublicKeyCredential & {
    antelope_public_key: string;
}>;
