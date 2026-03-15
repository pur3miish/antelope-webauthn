import authenticatorAssertion from "./authenticator-assertion.js";
import assertBrowserCompatibility from "./browser-compatability.js";
import createAntelopeSignature from "./create-antelope-signature.js";
import { credentialIdToUint8Array } from "./credential-id-to-uint8array.js";
import { hexToUint8Array } from "./hex-to-uint8array.js";

export type device_key = {
  public_key: string;
  credential_id: string;
};

/**
 * Function takes a `device_key` type and a hash(challenge) and initates a request to sign from a credential.
 * This enables users to generate an antelope compatible signature using their webauthn credentials.
 * The signature can then be verified on chain using the public key associated with the credential.
 */
export default async function antelopeSign(
  device_keys: device_key[],
  hash: Uint8Array | string
): Promise<string> {
  assertBrowserCompatibility();

  const allowCredentials = device_keys.map((key) => ({
    id: credentialIdToUint8Array(key.credential_id),
    type: "public-key" as PublicKeyCredentialType,
    alg: -7 as COSEAlgorithmIdentifier,
  }));

  const assertation = (await authenticatorAssertion({
    publicKey: {
      allowCredentials,
      challenge: typeof hash == "string" ? hexToUint8Array(hash) : hash,
      timeout: 6e4,
      userVerification: "required",
    },
  } as CredentialRequestOptions)) as PublicKeyCredential;

  const response = assertation.response as AuthenticatorAssertionResponse;
  const device_key = device_keys.find((x) => x.credential_id == assertation.id);
  if (!device_key?.public_key)
    throw new Error(
      "We were unable to produce a valid signature with the device keys you provided."
    );

  const antelope_signature = createAntelopeSignature(
    response,
    device_key.public_key
  );

  return antelope_signature;
}
