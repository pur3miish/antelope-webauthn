type device_key = {
    public_key: string;
    credential_id: string;
};
export default function createWebAuthnSignature(device_key: device_key, hash: Uint8Array | string): Promise<string>;
export {};
