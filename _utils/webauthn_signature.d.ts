export default function webAuthSig({ authenticatorData, signature, clientDataJSON, }: AuthenticatorAssertionResponse, public_key: string): Promise<string>;
interface WaSignatureArgs {
    r: Uint8Array;
    s: Uint8Array;
    v: 0 | 1;
    authenticatorData: Uint8Array | ArrayBuffer;
    clientDataJSON: Uint8Array | ArrayBuffer;
}
/**
 * Serialize signature into an Antelope SIG_WA signature.
 */
export declare function serialize_wa_signature({ r, s, v, authenticatorData, clientDataJSON, }: WaSignatureArgs): Promise<string>;
export {};
