/**
 * Verifies an Antelope `SIG_WA_…` signature against a `PUB_WA_…` public key
 * using the browser's native `crypto.subtle` ECDSA implementation.
 *
 * The function:
 * 1. Base58-decodes and deserialises the signature wire format to recover
 *    `r`, `s`, `authenticatorData`, and `clientDataJSON`.
 * 2. Recomputes `SHA-256(authenticatorData || SHA-256(clientDataJSON))` — the
 *    same digest that the authenticator signed.
 * 3. Reconstructs the uncompressed P-256 public key from the compressed
 *    `PUB_WA_…` bytes using the Tonelli–Shanks algorithm.
 * 4. Delegates the final ECDSA verification to `crypto.subtle.verify`.
 *
 * Can be used client-side or in any environment with a Web Crypto API
 * (`crypto.subtle`), including Node.js ≥ 18 and Cloudflare Workers.
 *
 * @param signature - A `SIG_WA_…` Antelope signature string, as returned by
 *   {@link antelopeSign} or {@link createAntelopeSignature}.
 * @param public_key - The `PUB_WA_…` Antelope public key string of the
 *   credential that produced the signature.
 * @returns `true` if the signature is cryptographically valid for the given
 *   public key; `false` otherwise.
 * @throws {Error} If the browser / runtime does not support the WebAuthn
 *   compatibility check (`assertBrowserCompatibility`).
 *
 * @example
 * ```ts
 * import { verifyAntelopeSignature } from "antelope-webauthn";
 *
 * const isValid = await verifyAntelopeSignature(
 *   "SIG_WA_...",
 *   "PUB_WA_6eRs44BYTJKPrGTCqR5TuMSQbCrZsNdNSXTHNuNitSdTfVQe8JSf89qy7JwxEnFW7"
 * );
 * console.log(isValid); // true
 * ```
 */
export default function verifyAntelopeSignature(signature: string, public_key: string): Promise<boolean>;
