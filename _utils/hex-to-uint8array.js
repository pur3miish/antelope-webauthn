export function hexToUint8Array(hex) {
    if (hex.startsWith("0x")) {
        hex = hex.slice(2);
    }
    if (hex.length % 2 !== 0) {
        throw new Error("Invalid hex string");
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        const byte = hex.slice(i * 2, i * 2 + 2);
        bytes[i] = parseInt(byte, 16);
    }
    return bytes;
}
