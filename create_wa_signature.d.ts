export type device_key = {
    id: string;
    public_key: string;
    credential_id: string;
};
export default function createWebAuthnSignature(device_keys: device_key[], hash: Uint8Array | string): Promise<string>;
