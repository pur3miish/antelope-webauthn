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
export default function classifyWebAuthnCredential(input: ClassifyWebAuthnCredentialInput): CredentialClassification;
