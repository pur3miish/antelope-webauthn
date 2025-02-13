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
export default function createWebAuthnKey({ id, email, displayName, relayingParty, challenge, }: createWebAuthnKeyArgs): Promise<device_key>;
