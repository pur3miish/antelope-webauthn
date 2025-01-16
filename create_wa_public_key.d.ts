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
export default function createWebAuthnKey({ id, email, displayName, relayingParty, challenge, }: createWebAuthnKeyArgs): Promise<{
    public_key: string;
    credential_id: string;
}>;
export {};
