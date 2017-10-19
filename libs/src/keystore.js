const crypto = require('crypto');
const scrypt= require('scryptsy');
const ethereuUtil = require('ethereumjs-util');
const uuid = require('uuid/v4');

exports.pkeyToKeystore = function (privateKey, address, password) {

    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    var derivedKey;
    const kdfparams = {
            dklen: 32,
            salt: salt.toString('hex')
        }
    ;
    kdfparams.n = 1024;
    kdfparams.r = 8;
    kdfparams.p = 1;
    derivedKey = scrypt(
        new Buffer(password),
        salt,
        kdfparams.n,
        kdfparams.r,
        kdfparams.p,
        kdfparams.dklen
    );
    const cipher = crypto.createCipheriv('aes-128-ctr', derivedKey.slice(0, 16), iv);
    if (!cipher) {
        throw new Error('Unsupported cipher');
    }
    const ciphertext = Buffer.concat([cipher.update(privateKey), cipher.final()]);
    const mac = ethereuUtil.sha3(
        Buffer.concat([derivedKey.slice(16, 32), new Buffer(ciphertext, 'hex')])
    );
    return {
        version: 3,
        id: uuid({
            random: crypto.randomBytes(16)
        }),
        address,
        Crypto: {
            ciphertext: ciphertext.toString('hex'),
            cipherparams: {
                iv: iv.toString('hex')
            },
            cipher: 'aes-128-ctr',
            kdf: 'scrypt',
            kdfparams,
            mac: mac.toString('hex')
        }
    };
};