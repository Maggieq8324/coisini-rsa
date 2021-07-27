/**
 * RSA 分段解密辅助
 * @param hex
 * @returns {[]}
 */

/**
 * 16进制转byte数组
 */
function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

/**
 * byte数组转16进制
 * @param bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
    let hex = [];
    for (let i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

/**
 * base64转btye数组
 * @param base64
 * @returns {Uint8Array}
 */
function base64ToArrayBuffer(base64) {
    let binary_string = window.atob(base64);
    let len = binary_string.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }

    return bytes;
}

export {
    hexToBytes,
    bytesToHex,
    base64ToArrayBuffer
}