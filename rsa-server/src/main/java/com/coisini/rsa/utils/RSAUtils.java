package com.coisini.rsa.utils;

import com.alibaba.fastjson.JSONObject;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @Description RSA加密算法
 * @author coisini
 * @date Jul 5, 2021
 * @Version 1.0
 */
public class RSAUtils {

    private static final String ALGO = "RSA";
    private static final String CHARSET = "UTF-8";

    /**
     * 公钥 由generateKeyPair()生成
     */
    private static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaaI4MBywkCjIppZnraqN3pbrcZTq/t0+aMBo8K3pK9BDD6XkM6N2Yfcva7BSFbUWuAcI7piXak0UKn9CElDuhNzUSgQn4IXKxIt3Iva5cV83qYumj+0yRjjLT8Muu1Y1rgBZjY9oBwhVoV+Twg25+UJ+6Q6HM4xTwQQJDoyy4jwIDAQAB";

    /**
     * 私钥 由generateKeyPair()生成
     */
    private static final String PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJpojgwHLCQKMimlmetqo3elutxlOr+3T5owGjwrekr0EMPpeQzo3Zh9y9rsFIVtRa4BwjumJdqTRQqf0ISUO6E3NRKBCfghcrEi3ci9rlxXzepi6aP7TJGOMtPwy67VjWuAFmNj2gHCFWhX5PCDbn5Qn7pDoczjFPBBAkOjLLiPAgMBAAECgYBnBBKhG7frY5IMDxwd4Euna767hB4qAlbte+JE+ozgrOzyiDXm0wXk0yjKqm8WhczTRwEbYsImjdKmP/GSQoN1AU7yEzM8j0Jgq46m9ZVrHhu2NpuZpr+XueWnA6FNz6tybBgcCwA4t8dvfbOrvjqhrCu01O1xWIpjronyFBN4IQJBAPGuF58xjXyANnp5YU8NhUQ73tTIveRlOpMXDSYkf9lWG26XIGUIsTe0f5jssiNmYtxG+lUm9LLfZgOLcrVkDZ0CQQCjjrBNMXub49efVTCg+nCGT2QXW2BHg/qs5vu8Y34LUHoD/hoEJ+AOWOdnhpRoYOpBwJAm3Gu4a1VmZGGafp0bAkAdfY3aWhSWtZpwNXF/UPoLCnc1Zc1uGkAchLqRBfEn1w7/3qcQTRA66OaNBYzzLuIvWOXhECDZ1tK+6fw0UCItAkAOLibW6n1fDKf7JnWq30u2OVfiNofoa2bmarhUowOgk3+grP0wcwyX8dlOPnrLeeuVe86DsASe3p9u2zEjJesVAkEAhkLiv4TXrC1QlJl7ghksUfFmdT7M4Zxlzj10ConMgq68HkLdmn2nNLsjhUHGwJe3EqM6aozn4zw/Z7uPIT9Fsw==";

    /**
     * 生成密钥对
     * @throws NoSuchAlgorithmException
     */
    private static void generateKeyPair() throws NoSuchAlgorithmException {
        // KeyPairGenerator 类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGO);
        // 初始化密钥对生成器，密钥大小为 96-1024 位
        keyPairGen.initialize(1024, new SecureRandom());
        // 生成一个密钥对，保存在 keyPair 中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        // 得到私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // 得到公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String publicKeyString = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
        // 得到私钥字符串
        String privateKeyString = new String(Base64.getEncoder().encode((privateKey.getEncoded())));
        System.out.println(publicKeyString);
        System.out.println(privateKeyString);
    }

    /**
     * RSA公钥加密
     * @param data 加密字符串
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    private static String encryptByPublicKey(String data) throws Exception {
        // base64 编码的公钥
        byte[] decoded = Base64.getDecoder().decode(PUBLIC_KEY);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance(ALGO).generatePublic(new X509EncodedKeySpec(decoded));
        // RSA加密
        Cipher cipher = Cipher.getInstance(ALGO);
        // 公钥加密
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(CHARSET)));
    }

    /**
     * RSA私钥解密
     * @param data 加密字符串
     * @return 明文
     * @throws Exception 解密过程中的异常信息
     */
    private static String decryptByPrivateKey(String data) throws Exception {
        byte[] inputByte = Base64.getDecoder().decode(data.getBytes(CHARSET));
        // base64 编码的私钥
        byte[] decoded = Base64.getDecoder().decode(PRIVATE_KEY);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance(ALGO).generatePrivate(new PKCS8EncodedKeySpec(decoded));
        // RSA 解密
        Cipher cipher = Cipher.getInstance(ALGO);
        // 私钥解密
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return new String(cipher.doFinal(inputByte));
    }

    /**
     * 私钥加密
     * 前端公钥解密
     * @param data 加密字符串
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    public static String encryptByPrivateKey(String data) throws Exception {
        // 获取私钥
        PrivateKey privateKey = getPrivateKey(PRIVATE_KEY);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] cipherText = cipher.doFinal(data.getBytes());
        String cipherStr = Base64.getEncoder().encodeToString(cipherText);
        return cipherStr;
    }

    /**
     * 公钥解密
     * @param data 解密字符串
     * @return 明文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decryptByPublicKey(String data) throws Exception {
        // 获取公钥
        PublicKey publicKey = getPublicKey(PUBLIC_KEY);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] cipherText = Base64.getDecoder().decode(data);
        byte[] decryptText = cipher.doFinal(cipherText);
        return new String(decryptText);
    }

    /**
     * 将base64编码后的私钥字符串转成PrivateKey实例
     * @param privateKey 私钥
     * @return PrivateKey实例
     * @throws Exception 异常信息
     */
    private static PrivateKey getPrivateKey(String privateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGO);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 将base64编码后的公钥字符串转成PublicKey实例
     * @param publicKey 公钥
     * @return PublicKey实例
     * @throws Exception 异常信息
     */
    private static PublicKey getPublicKey(String publicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGO);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 私钥分段加密
     * @param content
     * @return
     * @throws Exception
     */
    public static String encryptLongByPrivateKey(String content) throws Exception {
        // 获取私钥
        PrivateKey privateKey = getPrivateKey(PRIVATE_KEY);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] data = content.getBytes("UTF-8");
        // 加密时超过117字节就报错。为此采用分段加密的办法来加密
        byte[] enBytes = null;
        for (int i = 0; i < data.length; i += 117) {
            // 注意要使用2的倍数，否则会出现加密后的内容再解密时为乱码
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 117));
            enBytes = ArrayUtils.addAll(enBytes, doFinal);
        }
        return Base64.getEncoder().encodeToString(enBytes);
    }

    /**
     * 公钥分段解密
     * @param content
     * @return
     * @throws Exception
     */
    public static String decryptLongByPublicKey(String content) throws Exception {
        //获取公钥
        PublicKey publicKey = getPublicKey(PUBLIC_KEY);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] data =  Base64.getDecoder().decode(content);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i += 128) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 128));
            sb.append(new String(doFinal));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        String data = "RSA encrypt!";
        try {
            // generateKeyPair();

            String encryDataByPublicKey = encryptByPublicKey(data);
            System.out.println("encryDataByPublicKey: " + encryDataByPublicKey);
            String decryDataByPrivateKey = decryptByPrivateKey(encryDataByPublicKey);
            System.out.println("decryDataByPrivateKey: " + decryDataByPrivateKey);

            String encryDataByPrivateKey = encryptByPrivateKey(data);
            System.out.println("encryDataByPrivateKey: " + encryDataByPrivateKey);
            String decryDataByPublicKey = decryptByPublicKey(encryDataByPrivateKey);
            System.out.println("decryDataByPublicKey: " + decryDataByPublicKey);


            System.out.println("========分段加解密==========");

            Map<String,Object> map = new HashMap<>();
            map.put("name", "Cosini");
            map.put("phone", "13888888888");
            String content = JSONObject.toJSONString(map);

            // 密文
            String cipherText = RSAUtils.encryptLongByPrivateKey(content);
            System.out.println("encryptLongByPrivateKey: " + cipherText);

            // 明文
            String plainText = RSAUtils.decryptLongByPublicKey(cipherText);
            System.out.println("decryptLongByPublicKey: " + plainText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
