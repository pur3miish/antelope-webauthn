export type CredentialKind = "hardware-security-key" | "device-bound" | "synced-passkey" | "unknown";
export type CredentialClassification = {
    kind: CredentialKind;
    confidence: "high" | "medium" | "low";
    reason: string;
    flags: {
        userPresent: boolean;
        userVerified: boolean;
        backupEligible: boolean;
        backupState: boolean;
        attestedCredentialData: boolean;
        extensionsIncluded: boolean;
        signCount: number;
    };
};
export type ClassifyWebAuthnCredentialInput = {
    response: Pick<AuthenticatorAssertionResponse, "authenticatorData">;
    /**
     * Usually taken from PublicKeyCredential.authenticatorAttachment
     */
    authenticatorAttachment?: "platform" | "cross-platform" | null;
    /**
     * Optional registration-time hint if you stored transports.
     */
    transports?: string[] | null;
};
/**
 * Classifies a WebAuthn credential based on its authenticator data and metadata.
 *
 * The classification is based on the backup eligibility and state flags in the authenticator data, as well as any available metadata about the authenticator attachment and transports. The function returns a classification of the credential along with a confidence level and reasoning for the classification.
 *
 * @param input - An object containing the authenticator response and optional metadata about the authenticator.
 * @returns A classification of the credential, including its kind, confidence level, reasoning, and relevant flags from the authenticator data.
 */
export default function classifyWebAuthnCredential(input: ClassifyWebAuthnCredentialInput): CredentialClassification;
