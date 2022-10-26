var AES = require("crypto-js/aes");
var SHA256 = require("crypto-js/sha256");
var CryptoJS = require("crypto-js");

const AES_KEY = "HELLO123";

export const encryptAES = (message) => {
  return AES.encrypt(message, AES_KEY).toString();
};

export const decryptAES = (message) => {
  const decrypted = CryptoJS.AES.decrypt(message, AES_KEY);
  if (decrypted) {
    try {
      console.log(decrypted);
      const str = decrypted.toString(CryptoJS.enc.Utf8);
      if (str.length > 0) {
        return str;
      } else {
        return "error 1";
      }
    } catch (e) {
      return "error 2";
    }
  }
  return "error 3";
};

export const applyHash = (message) => {
  return SHA256(message).toString();
};

export const checkHash = (message) => {
  let actual_message = message.substring(64);
  let hash = message.substring(0, 64);
  if (applyHash(actual_message) != hash) {
    return "INCORRECT MESSAGE";
  } else {
    return actual_message;
  }
};
