/**
 * Extracts the s and r signatures from a der encoded signature
 */
export default function decodeDER(der: Uint8Array): {
    r: Uint8Array;
    s: Uint8Array;
};
