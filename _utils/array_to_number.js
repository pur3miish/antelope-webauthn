export const array_to_number = (array) => BigInt(`0x${array.reduce((acc, i) => (acc += i.toString(16).padStart(2, "0")), "")}`);
export function bigint_to_array(bigint) {
    const length = Math.ceil(bigint.toString(2).length / 8);
    const buffer = new ArrayBuffer(length);
    const view = new DataView(buffer);
    for (let i = length - 1; i >= 0; i--) {
        view.setUint8(i, Number(bigint & 0xffn));
        bigint >>= 8n;
    }
    return new Uint8Array(buffer);
}
