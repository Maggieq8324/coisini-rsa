/**
 * 非对称加密-RSA
 * 后端私钥加密 - 前端公钥解密
 */
import { JSEncrypt } from '../libs/jsencrypt/lib/JSEncrypt'
import { base64ToArrayBuffer } from '../libs/jsencrypt/lib/JSEncryptRSAassist';

const PUBLICKEY = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaaI4MBywkCjIppZnraqN3pbrcZTq/t0+aMBo8K3pK9BDD6XkM6N2Yfcva7BSFbUWuAcI7piXak0UKn9CElDuhNzUSgQn4IXKxIt3Iva5cV83qYumj+0yRjjLT8Muu1Y1rgBZjY9oBwhVoV+Twg25+UJ+6Q6HM4xTwQQJDoyy4jwIDAQAB';

export const RSADECRY = {
    /**
     * 公钥解密
     * @param secretWord
     * @returns {解密|string|false|PromiseLike<ArrayBuffer>}
     */
    decryptByPublicKey: function (val = '') {
        if (val === '') {
            return '';
        }
        let encrypt = new JSEncrypt();

        encrypt.setPublicKey(PUBLICKEY);

        //使用公钥对私钥加密后的数据解密
        return encrypt.decrypt(val);
    },
    /**
     * 公钥分段解密
     * @returns {boolean|undefined}
     * @param val
     */
    decryptLongByPublicKey: function (val = '') {
        if(val === ''){
            return '';
        }
        let encrypt = new JSEncrypt()
        encrypt.setPublicKey(PUBLICKEY) // 设置公钥

        let decryptStr = encrypt.decryptLong(base64ToArrayBuffer(val)); // val要解密的数据 先转为byte数组在进行解码

        return decryptStr ? decryptStr : val;
    }


}

