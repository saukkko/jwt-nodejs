export const JSONToBase64UrlString = (
  o: Record<string, unknown>,
  enc?: BufferEncoding
) => Buffer.from(JSON.stringify(o), enc || "utf8").toString("base64url");

export const base64UrlStringToJSON = (str: string, enc?: BufferEncoding) =>
  JSON.parse(Buffer.from(str, "base64url").toString(enc || "utf8"));
