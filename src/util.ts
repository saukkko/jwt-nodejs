export const JSONToBase64UrlString = (
  o: Record<string, unknown>,
  enc?: BufferEncoding
) => base64UrlEncode(JSON.stringify(o), enc);

export const base64UrlStringToJSON = (base64: string, enc?: BufferEncoding) =>
  JSON.parse(base64UrlDecode(base64, enc));

export const base64UrlEncode = (str: string, enc?: BufferEncoding) =>
  Buffer.from(str, enc || "utf8").toString("base64url");

export const base64UrlDecode = (base64: string, enc?: BufferEncoding) =>
  Buffer.from(base64, "base64url").toString(enc || "utf8");

export const base64Decode = (base64: string, enc?: BufferEncoding) =>
  Buffer.from(base64, "base64").toString(enc || "utf8");

export const base64Encode = (str: string, enc?: BufferEncoding) =>
  Buffer.from(str, enc || "utf8").toString("base64");

export const hmacAlgos = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512",
};

export const rsaAlgos = {
  RS256: "rsa-sha256",
  RS384: "rsa-sha384",
  RS512: "rsa-sha512",
};
export const ecdsaAlgos = {
  ES256: "ecdsa256",
  ES384: "ecdsa384",
  ES512: "ecdsa512",
};
export const rsaPssAlgos = {
  PS256: "unknown",
  PS384: "unknown",
  PS512: "unknown",
};
