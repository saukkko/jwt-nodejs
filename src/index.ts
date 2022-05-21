import { randomBytes } from "crypto";
import { signJWT, verifyJWT } from "./sign.js";
import { JOSEHeader } from "./types.js";
import { decryptDataAEAD, encryptDataAEAD } from "./encrypt.js";
import { base64Decode } from "./util.js";

/* encryptDataAEAD(
  "salasana",
  Buffer.from("there is no secret here").toString("base64"),
  { foo: "bar" },
  "aes-128-gcm"
)
  .then((enc) => {
    console.log("Encoded and encrypted:\n" + enc);
    decryptDataAEAD("salasana", enc, "aes-128-gcm")
      .then((dec) => {
        console.log("Decrypted:\n" + dec);
      })
      .catch(console.error);
  })
  .catch(console.error);
 */

const header: JOSEHeader = {
  alg: "HS512",
  typ: "JWT",
  enc: "chacha20-poly1305",
};
const payload = {
  iss: "Sauli",
  exp: Number((Date.now() / 1000 + 3600).toFixed(0)),
  data: "Epstein did not kill himself",
};

const jwt = Buffer.from(await signJWT(header, payload, "secret")).toString(
  "hex"
);
console.log(jwt);

const encJwt = await encryptDataAEAD("very secret", jwt, header, header.enc);
console.log(encJwt);

const decJwt = await decryptDataAEAD("very secret", encJwt, header.enc);
if (Buffer.isBuffer(decJwt)) {
  const token = decJwt.toString("base64");

  console.log(Buffer.from(token, "hex").toString());
}
