import { ok } from "assert";
import { webcrypto } from "crypto";

import verifySignature from "../src/verify_wa_signature";

it("Verify WA signatures", async () => {
  global.window = { crypto: { subtle: webcrypto.subtle } };
  const public_key =
    "PUB_WA_6eRs44BYTJKPrGTCqR5TuMSQbCrZsNdNSXTHNuNitSdTfVQe8JSf89qy7JwxEnFW7";

  const signature =
    "SIG_WA_JMTejvQoxh1JWw5d5x1F54v5jfguXPZJ4CqTry5b64cXUhSivXntpAmVyaMhkNi5a3CwKDLoAzrH7gjBWPGMzJ3zooN9ZjzmfNdjMiDKfj5xokkCJ1mxjPRUJ3q1eCqiK4Lb7a9XE9LQn8oYu6m69WjiHkNQmScTVHKRh7bFNShvV2tNBRj3g9pn8E6s53dxnUYo88Y8tDFHn7t6UvkZXR7CeYmmdYMcyxquFcjLjga3trkQo6zaCA23KAprixS87fV3BkuvrkvzQC4DqdrUv8dQAatyfPZNNkWWX25fxK8VmDMugfiG4nDWrNkceLHrgAbXqLuwccdmu";

  ok(await verifySignature(signature, public_key));

  ok(
    (await verifySignature(
      signature,
      "PUB_WA_2ZTU7dUiALKzd4CXXRzAqtmzvP9N9873VEgUhwFajs2BFZXSSL6Eu3Y3mUrm59Mf9MC9"
    )) == false
  );

  delete global.window;
});
