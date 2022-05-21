import { createHmac, createSign, verify } from "crypto";
import {
  JSONToBase64UrlString,
  hmacAlgos,
  rsaAlgos,
  ecdsaAlgos,
  rsaPssAlgos,
  base64UrlStringToJSON,
} from "./util.js";
import type { JOSEHeader } from "./types.js";
import { KeyObject } from "crypto";

/**
 *
 * @param header JOSE Header according to RFC 7519
 * @param payload JSON formatted payload
 * @param secret Secret used for signing.
 * @returns JWT
 */
export const signJWT = async (
  header: JOSEHeader,
  payload: Record<string, unknown>,
  secret: string | KeyObject
): Promise<string> => {
  return new Promise((resolve, reject) => {
    const data = [
      JSONToBase64UrlString(header),
      JSONToBase64UrlString(payload),
    ];

    try {
      let algo = Object.entries(hmacAlgos).find(
        (hmac) => header.alg === hmac[0]
      );
      if (algo && typeof secret === "string")
        data.push(signWithHmac(algo[1], secret, data));

      algo = Object.entries(rsaAlgos).find((rsa) => header.alg === rsa[0]);
      if (algo && secret instanceof KeyObject)
        data.push(signWithRsa(algo[1], secret, data));

      // TODO: Implement everything and tidy up
      algo = Object.entries(ecdsaAlgos).find(
        (ecdsa) => header.alg === ecdsa[0]
      );
      if (algo) throw new Error("ECDSA signing not yet implemented");

      algo = Object.entries(rsaPssAlgos).find(
        (rsaPss) => header.alg === rsaPss[0]
      );
      if (algo) throw new Error("RSAPSS signing not yet implemented");

      return resolve(data.join("."));
    } catch (err) {
      reject(err);
    }
    reject("Invalid algorithm");
  });
};

export const verifyJWT = async (
  token: string,
  secret: string,
  pubKey?: KeyObject
): Promise<boolean> => {
  return new Promise((resolve, reject) => {
    try {
      const [encHeader, encPayload, recvSignature] = token.split(".");
      const header: JOSEHeader = base64UrlStringToJSON(encHeader);

      let signature;

      let algo = Object.entries(hmacAlgos).find(
        (hmac) => header.alg === hmac[0]
      );
      if (algo)
        signature = signWithHmac(algo[1], secret, [encHeader, encPayload]);

      algo = Object.entries(rsaAlgos).find((rsa) => header.alg === rsa[0]);
      if (algo && pubKey)
        resolve(
          verify(
            algo[1],
            Buffer.from([encHeader, encPayload].join(".")),
            pubKey,
            Buffer.from(recvSignature, "base64")
          )
        );

      resolve(signature === recvSignature);
    } catch (err) {
      reject(err);
    }
  });
};

const signWithHmac = (algo: string, secret: string, data: string[]) => {
  const hmac = createHmac(algo, Buffer.from(secret, "base64"));
  hmac.update(data.join("."));

  return hmac.digest("base64url");
};

const signWithRsa = (algo: string, privateKey: KeyObject, data: string[]) => {
  const rsa = createSign(algo);
  rsa.update(data.join("."));

  return rsa.sign(privateKey).toString("base64url");
};
