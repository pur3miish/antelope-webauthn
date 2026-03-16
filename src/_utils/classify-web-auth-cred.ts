/**
 * Describes the broad storage / portability category of a WebAuthn credential.
 *
 * - `"synced-passkey"` — backed up and synced across devices (e.g. iCloud Keychain, Google Password Manager).
 * - `"device-bound"` — locked to a single platform authenticator or not currently synced.
 * - `"hardware-security-key"` — a roaming hardware token (YubiKey, etc.).
 * - `"unknown"` — insufficient metadata to determine the category.
 */
export type CredentialKind =
  | "hardware-security-key"
  | "device-bound"
  | "synced-passkey"
  | "unknown";

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

function parseAuthenticatorData(authData: Uint8Array) {
  if (authData.length < 37) throw new Error("Invalid authenticatorData length");

  const flags = authData[32];
  const signCount = new DataView(
    authData.buffer,
    authData.byteOffset + 33,
    4
  ).getUint32(0, false);

  return {
    userPresent: !!(flags & 0x01),
    userVerified: !!(flags & 0x04),
    backupEligible: !!(flags & 0x08),
    backupState: !!(flags & 0x10),
    attestedCredentialData: !!(flags & 0x40),
    extensionsIncluded: !!(flags & 0x80),
    signCount,
  };
}

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
export default function classifyWebAuthnCredential(
  input: ClassifyWebAuthnCredentialInput
): CredentialClassification {
  const authData = new Uint8Array(input.response.authenticatorData);
  const parsed = parseAuthenticatorData(authData);

  const { backupEligible, backupState } = parsed;
  const { authenticatorAttachment, transports } = input;

  if (backupEligible && backupState) {
    return {
      kind: "synced-passkey",
      confidence: "high",
      reason:
        "Credential is backup-eligible and currently backed up, which indicates a synced multi-device passkey.",
      flags: parsed,
    };
  }

  if (backupEligible && !backupState) {
    return {
      kind: "device-bound",
      confidence: "medium",
      reason:
        "Credential is backup-eligible but not currently reported as backed up. This is often treated as device-bound for UX purposes, though technically it is still a multi-device credential class.",
      flags: parsed,
    };
  }

  if (!backupEligible) {
    if (authenticatorAttachment === "cross-platform") {
      return {
        kind: "hardware-security-key",
        confidence: "high",
        reason:
          "Credential is not backup-eligible and authenticatorAttachment is cross-platform, which strongly suggests a roaming hardware security key.",
        flags: parsed,
      };
    }

    if (authenticatorAttachment === "platform") {
      return {
        kind: "device-bound",
        confidence: "high",
        reason:
          "Credential is not backup-eligible and authenticatorAttachment is platform, which indicates a device-bound platform authenticator.",
        flags: parsed,
      };
    }

    if (transports?.some((t) => ["usb", "nfc", "ble", "hybrid"].includes(t))) {
      return {
        kind: "hardware-security-key",
        confidence: "medium",
        reason:
          "Credential is not backup-eligible and transports suggest a roaming authenticator, but authenticatorAttachment was not provided.",
        flags: parsed,
      };
    }

    if (transports?.includes("internal")) {
      return {
        kind: "device-bound",
        confidence: "medium",
        reason:
          "Credential is not backup-eligible and transports suggest an internal platform authenticator, but authenticatorAttachment was not provided.",
        flags: parsed,
      };
    }

    return {
      kind: "unknown",
      confidence: "low",
      reason:
        "Credential is not backup-eligible, so it is single-device, but there is not enough metadata to determine whether it is a hardware security key or a built-in device-bound credential.",
      flags: parsed,
    };
  }

  return {
    kind: "unknown",
    confidence: "low",
    reason: "Insufficient data to classify credential.",
    flags: parsed,
  };
}
