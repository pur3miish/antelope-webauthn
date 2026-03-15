/**
 * verifies an antelope compatible signature produced by the `antelopeSign` function. This can be used to verify signatures on the client side, or in a server environment. It takes the signature and the public key associated with the credential that produced the signature and returns a boolean indicating whether the signature is valid or not.
 * @param signature
 * @param public_key
 * @returns
 */
export default function verifyAntelopeSignature(signature: string, public_key: string): Promise<boolean>;
