import base58_to_binary from "base58-js/base58_to_binary.js";
import binary_to_base58 from "base58-js/binary_to_base58.js";
import varuint32 from "eosio-wasm-js/varuint32.js";
import ripemd160 from "ripemd160-js/ripemd160.js";
import { array_to_number } from "./array_to_number.js";
import calculateRecID from "./calculate_recovery_id.js";
import decodeDER from "./decode-der.js";
import sha256 from "./sha256.js";
export default async function webAuthSig({ authenticatorData, signature, clientDataJSON, }, public_key) {
    const { r, s } = decodeDER(new Uint8Array(signature));
    const serializeArg = { r, s, clientDataJSON, authenticatorData };
    const public_key_bytes = base58_to_binary(public_key.replace("PUB_WA_", ""));
    const clientDataHash = await sha256(new Uint8Array(clientDataJSON));
    const hash = await sha256(Uint8Array.from([...new Uint8Array(authenticatorData), ...clientDataHash]));
    const rec_id = calculateRecID(public_key_bytes.slice(0, 33), { r: array_to_number(r), s: array_to_number(s) }, hash);
    return serialize_wa_signature({ v: rec_id, ...serializeArg });
}
/**
 * Serialize signature into an Antelope SIG_WA signature.
 */
export async function serialize_wa_signature({ r, s, v, authenticatorData, clientDataJSON, }) {
    const sig = Uint8Array.from([
        v + 27 + 4,
        ...r,
        ...s,
        // @ts-expect-error - I want to check this
        ...varuint32(authenticatorData.length ?? authenticatorData.byteLength)
            .match(/[a-z0-9]{2}/gmu)
            .map((i) => Number(`0x${i}`)),
        ...new Uint8Array(authenticatorData),
        // @ts-expect-error - I want to check this
        ...varuint32(clientDataJSON.length ?? clientDataJSON.byteLength)
            .match(/[a-z0-9]{2}/gmu)
            .map((i) => Number(`0x${i}`)),
        ...new Uint8Array(clientDataJSON),
    ]);
    const WA = [87, 65];
    const checksum = await (await ripemd160(Uint8Array.from([...sig, ...WA]))).slice(0, 4);
    return ("SIG_WA_" +
        binary_to_base58(Uint8Array.from([...sig, ...checksum])));
}
