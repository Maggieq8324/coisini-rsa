/**
 * 非对称加密-RSA
 * 前端公钥加密 - 后端私钥解密
 *
 */
import { JSEncrypt } from 'jsencrypt/lib/JSEncrypt'

const PUBLIC_KEY = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaaI4MBywkCjIppZnraqN3pbrcZTq/t0+aMBo8K3pK9BDD6XkM6N2Yfcva7BSFbUWuAcI7piXak0UKn9CElDuhNzUSgQn4IXKxIt3Iva5cV83qYumj+0yRjjLT8Muu1Y1rgBZjY9oBwhVoV+Twg25+UJ+6Q6HM4xTwQQJDoyy4jwIDAQAB';
const PRIVATE_KEY = 'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJpojgwHLCQKMimlmetqo3elutxlOr+3T5owGjwrekr0EMPpeQzo3Zh9y9rsFIVtRa4BwjumJdqTRQqf0ISUO6E3NRKBCfghcrEi3ci9rlxXzepi6aP7TJGOMtPwy67VjWuAFmNj2gHCFWhX5PCDbn5Qn7pDoczjFPBBAkOjLLiPAgMBAAECgYBnBBKhG7frY5IMDxwd4Euna767hB4qAlbte+JE+ozgrOzyiDXm0wXk0yjKqm8WhczTRwEbYsImjdKmP/GSQoN1AU7yEzM8j0Jgq46m9ZVrHhu2NpuZpr+XueWnA6FNz6tybBgcCwA4t8dvfbOrvjqhrCu01O1xWIpjronyFBN4IQJBAPGuF58xjXyANnp5YU8NhUQ73tTIveRlOpMXDSYkf9lWG26XIGUIsTe0f5jssiNmYtxG+lUm9LLfZgOLcrVkDZ0CQQCjjrBNMXub49efVTCg+nCGT2QXW2BHg/qs5vu8Y34LUHoD/hoEJ+AOWOdnhpRoYOpBwJAm3Gu4a1VmZGGafp0bAkAdfY3aWhSWtZpwNXF/UPoLCnc1Zc1uGkAchLqRBfEn1w7/3qcQTRA66OaNBYzzLuIvWOXhECDZ1tK+6fw0UCItAkAOLibW6n1fDKf7JnWq30u2OVfiNofoa2bmarhUowOgk3+grP0wcwyX8dlOPnrLeeuVe86DsASe3p9u2zEjJesVAkEAhkLiv4TXrC1QlJl7ghksUfFmdT7M4Zxlzj10ConMgq68HkLdmn2nNLsjhUHGwJe3EqM6aozn4zw/Z7uPIT9Fsw==';

export const RSAENCRY = {
    /**
     * 公钥加密
     * @param val 需要加密的字符串
     * @return string 返回加密结果
     */
    encryptByPublicKey: function (val = '') {
        if(val === ''){
            return '';
        }
        let encrypt = new JSEncrypt(); // 新建JSEncrypt对象
        encrypt.setPublicKey(PUBLIC_KEY); // 设置公钥
        return encrypt.encrypt(val); // 对需要加密的数据进行加密
    },
    /**
     * 私钥解密
     * @param val
     * @returns {string|false|null|PromiseLike<ArrayBuffer>}
     */
    decryptByPrivateKey: function (val = '') {
        if(val === ''){
            return '';
        }
        let decrypt = new JSEncrypt(); // 新建JSEncrypt对象
        decrypt.setPrivateKey(PRIVATE_KEY); // 设置私钥
        return decrypt.decrypt(val); // 对需要解密的数据进行解密
    }
}

