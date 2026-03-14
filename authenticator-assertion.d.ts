/**
 * Creates a new webauthn signature response
 * @example
 * ```ts
 * const hexString = "0000000000000000000000000000000000000000000000000000000000000000";
 *
 * const assertation = await createPublicKeyCredential({
 *   publicKey: {
 *     allowCredentials: [
 *       {
 *         id: credentialIfToUint8Array("some-credential-id"),
 *         type: "public-key" as PublicKeyCredentialType,
 *         alg: -7 as COSEAlgorithmIdentifier,
 *       },
 *     ],
 *     challenge: hexToUint8Array(hexString),
 *     timeout: 6e4,
 *     userVerification: "required",
 *   },
 * });
 * ```
 */
export default function authenticatorAssertion(options: CredentialRequestOptions): Promise<PublicKeyCredential>;
