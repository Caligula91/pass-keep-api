const crypto = require('crypto');

const encrypt = (password) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    process.env.CRYPTO_ALGO,
    Buffer.from(process.env.CRYPTO_KEY),
    iv
  );
  let encrypted = cipher.update(password);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return { password: encrypted.toString('hex'), iv: iv.toString('hex') };
};

const decrypt = (encryptedData) => {
  const iv = Buffer.from(encryptedData.iv, 'hex');
  const encryptedText = Buffer.from(encryptedData.password, 'hex');
  const decipher = crypto.createDecipheriv(
    process.env.CRYPTO_ALGO,
    Buffer.from(process.env.CRYPTO_KEY),
    iv
  );
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
};

module.exports = {
  encrypt,
  decrypt,
};
