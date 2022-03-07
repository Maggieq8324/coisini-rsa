<template>
  <div class="hello">
    <h1>{{ msg }}</h1>
    <p>
      For a guide and recipes on how to configure / customize this project,<br>
      check out the
      <a href="https://cli.vuejs.org" target="_blank" rel="noopener">vue-cli documentation</a>.
    </p>
    <h3>Installed CLI Plugins</h3>
    <ul>
      <li><a href="https://github.com/vuejs/vue-cli/tree/dev/packages/%40vue/cli-plugin-babel" target="_blank" rel="noopener">babel</a></li>
      <li><a href="https://github.com/vuejs/vue-cli/tree/dev/packages/%40vue/cli-plugin-eslint" target="_blank" rel="noopener">eslint</a></li>
    </ul>
    <h3>Essential Links</h3>
    <ul>
      <li><a href="https://vuejs.org" target="_blank" rel="noopener">Core Docs</a></li>
      <li><a href="https://forum.vuejs.org" target="_blank" rel="noopener">Forum</a></li>
      <li><a href="https://chat.vuejs.org" target="_blank" rel="noopener">Community Chat</a></li>
      <li><a href="https://twitter.com/vuejs" target="_blank" rel="noopener">Twitter</a></li>
      <li><a href="https://news.vuejs.org" target="_blank" rel="noopener">News</a></li>
    </ul>
    <h3>Ecosystem</h3>
    <ul>
      <li><a href="https://router.vuejs.org" target="_blank" rel="noopener">vue-router</a></li>
      <li><a href="https://vuex.vuejs.org" target="_blank" rel="noopener">vuex</a></li>
      <li><a href="https://github.com/vuejs/vue-devtools#vue-devtools" target="_blank" rel="noopener">vue-devtools</a></li>
      <li><a href="https://vue-loader.vuejs.org" target="_blank" rel="noopener">vue-loader</a></li>
      <li><a href="https://github.com/vuejs/awesome-vue" target="_blank" rel="noopener">awesome-vue</a></li>
    </ul>
  </div>
</template>

<script>
import { RSAENCRY } from "../utils/RSAEncryption"
import { RSADECRY } from "../utils/RSADecryption"

export default {
  name: 'HelloWorld',
  props: {
    msg: String
  },
  mounted() {
    let data = "RSA encrypt!";

    let encryptDataByPublicKey = RSAENCRY.encryptByPublicKey(data);
    console.log("encryptDataByPublicKey: ", encryptDataByPublicKey)

    let decryptDataByPrivateKey = RSAENCRY.decryptByPrivateKey(encryptDataByPublicKey);
    console.log("decryptDataByPrivateKey: ", decryptDataByPrivateKey)

    let decryptData = "AwovsO+xeiFSQe6mN9RRCz3FFlMXdCMcrqbNChsc7PbMfCxSHpKWIHQ2IJ/tw8mFsuX84r7TSVhYXB9ATA7nqWxMnKJgkPu+nFXeXSnApjce0MjFtjLpl9wrklVrOL6L0cmzu3DthC44Opwj5EVWF9tjiH7YdKFVK/Q5HVPKcZk=";
    let decryptDataByPublicKey = RSADECRY.decryptByPublicKey(decryptData);
    console.log("decryptDataByPublicKey: ", decryptDataByPublicKey)

    console.log("===================")
    let encryptStr = 'Guihe55ygtchHRFhGaK/T/y4grsPkC+Xa4DhHUw7MQeIDMc1SUZsV/VJ7D5yDbjIjfZbygTkWhWXLF4fJdgooAClzp5Lbaqn8FrMsBHj2oTFgJ3IFGBfiWvBgT21xKgbRHOBCIlHLHRucZDNW4XdgTN6iFRWpHP5xal47M3TAthsk3rlpPO7QBsv/dznmLfkcvo5gYepOCBzj7tKdxyEhu+1GUUqgIHIC1mGTiCkDoAXocfbpObEMWRhAzpHdpkR5nH00Kn7iVKKdgcKStyBqCW1wTx4lURrd32yGUqmkIWGpFi7lwhitL1d3oSzz2UZFke/HgHVIYBGoiVPizEc8g==';
    let decryptLongByPublicKey = RSADECRY.decryptLongByPublicKey(encryptStr);
    console.log("decryptLongByPublicKey: ", decryptLongByPublicKey);
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}
ul {
  list-style-type: none;
  padding: 0;
}
li {
  display: inline-block;
  margin: 0 10px;
}
a {
  color: #42b983;
}
</style>
