export type device_key = {
    public_key: string;
    credential_id: string;
};
/**
 * Function takes a `device_key` type and a hash(challenge) and initates a request to sign from a credential.
 * This enables users to generate an antelope compatible signature using their webauthn credentials.
 * The signature can then be verified on chain using the public key associated with the credential.
 */
export default function antelopeSign(device_keys: device_key[], hash: Uint8Array | string): Promise<string>;
