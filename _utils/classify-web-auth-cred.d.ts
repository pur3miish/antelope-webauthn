/**
 * Describes the broad storage / portability category of a WebAuthn credential.
 *
 * - `"synced-passkey"` — backed up and synced across devices (e.g. iCloud Keychain, Google Password Manager).
 * - `"device-bound"` — locked to a single platform authenticator or not currently synced.
 * - `"hardware-security-key"` — a roaming hardware token (YubiKey, etc.).
 * - `"unknown"` — insufficient metadata to determine the category.
 */
export type CredentialKind = "hardware-security-key" | "device-bound" | "synced-passkey" | "unknown";
/**
 * The result returned by {@link classifyWebAuthnCredential}, describing the
 * inferred category of the credential along with supporting evidence.
 */
export type CredentialClassification = {
    /** The inferred credential category. */
    kind: CredentialKind;
    /** How confident the classification is given the available metadata. */
    confidence: "high" | "medium" | "low";
    /** Human-readable explanation of why this classification was chosen. */
    reason: string;
    /** Parsed authenticator data flags and sign counter for further inspection. */
    flags: {
        /** User presence test was performed (UP bit). */
        userPresent: boolean;
        /** User verification was performed (UV bit). */
        userVerified: boolean;
        /** Credential is eligible for backup / sync (BE bit). */
        backupEligible: boolean;
        /** Credential is currently backed up (BS bit). */
        backupState: boolean;
        /** Attested credential data is present in this response. */
        attestedCredentialData: boolean;
        /** Extension data is present in this response. */
        extensionsIncluded: boolean;
        /** Monotonically increasing signature counter; `0` if not tracked. */
        signCount: number;
    };
};
/** Input to {@link classifyWebAuthnCredential}. */
export type ClassifyWebAuthnCredentialInput = {
    /** The authenticator response from either registration or authentication. */
    response: Pick<AuthenticatorAssertionResponse, "authenticatorData">;
    /**
     * Usually taken from `PublicKeyCredential.authenticatorAttachment`.
     * Providing this improves classification confidence for non-backup-eligible
     * credentials.
     */
    authenticatorAttachment?: "platform" | "cross-platform" | null;
    /**
     * Optional registration-time transport hints (e.g. `["internal"]`,
     * `["usb", "nfc"]`). Providing these improves classification when
     * `authenticatorAttachment` is unavailable.
     */
    transports?: string[] | null;
};
/**
 * Classifies a WebAuthn credential as a synced passkey, device-bound credential,
 * or hardware security key by inspecting the authenticator data flags and any
 * available attachment / transport metadata.
 *
 * The classification logic follows the WebAuthn Level 3 backup eligibility (BE)
 * and backup state (BS) flag definitions:
 * - `BE=1, BS=1` → synced passkey (high confidence)
 * - `BE=1, BS=0` → device-bound for UX purposes, but technically multi-device class (medium)
 * - `BE=0` → single-device; further refined by `authenticatorAttachment` / `transports`
 *
 * This function is synchronous and has no browser-environment requirement — it
 * can be called in Node.js server environments as well.
 *
 * @param input - The authenticator response and optional metadata.
 *   See {@link ClassifyWebAuthnCredentialInput}.
 * @returns A {@link CredentialClassification} with `kind`, `confidence`,
 *   `reason`, and the raw parsed `flags`.
 * @throws {Error} If `authenticatorData` is shorter than 37 bytes (invalid).
 *
 * @example
 * ```ts
 * import { classifyWebAuthnCredential } from "antelope-webauthn";
 *
 * const classification = classifyWebAuthnCredential({
 *   response: assertionResponse,
 *   authenticatorAttachment: credential.authenticatorAttachment,
 * });
 *
 * if (classification.kind === "synced-passkey") {
 *   console.warn("This key is synced — consider requiring a hardware key for high-value actions.");
 * }
 * ```
 */
export default function classifyWebAuthnCredential(input: ClassifyWebAuthnCredentialInput): CredentialClassification;
