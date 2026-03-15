/**
 * Creates a new webauthn signature response by calling `navigator.credentials.get` with the provided options.
 * This function is used internally by the `antelopeSign` function to generate signatures using webauthn credentials.
 * It takes a `CredentialRequestOptions` object as input and returns a `PublicKeyCredential` containing the assertion response from the authenticator.
 */
export default function authenticatorAssertion(options: CredentialRequestOptions): Promise<PublicKeyCredential>;
