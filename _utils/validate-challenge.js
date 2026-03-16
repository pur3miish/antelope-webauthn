export function validateChallenge(challenge) {
    if (!challenge)
        throw new Error("Challenge is required.");
    if (challenge instanceof ArrayBuffer)
        return;
    if (challenge instanceof Uint8Array)
        return;
    throw new Error("Challenge must be an ArrayBuffer or Uint8Array.");
}
