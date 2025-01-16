export default function decodeLEB128(bytes) {
    let result = 0;
    let shift = 0;
    let byte;
    do {
        byte = bytes.shift();
        result |= (byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < 32 && byte & 0x40)
        result |= -1 << shift;
    return result;
}
