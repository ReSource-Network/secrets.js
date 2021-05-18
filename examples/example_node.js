var http = require('http');
var secrets = require('../secrets.js');

// Usage:
//    cd examples
//    node example_node.js
//
//  Visit http://127.0.0.1:1337/ in your browser.
//  You should see two identical keys displayed, one original
//  key and then a key that resulted from splitting and combining shares.
//
var cryptojs = require("crypto-js");
let ph = require('../pohlig-hellman/bin/index');
let util = require('../pohlig-hellman/bin/util/index');
// const jsbn_1 = require("jsbn");
// function bufferToBigInt(buffer) {
//   return new jsbn_1.BigInteger(buffer.toString('hex'), 16);
// }

// Use some client known data for entropy
function getPiiHash() {
  let uname = 'someuser'
  let password = 'somesecret'
  let global_client_resource_salt = 'F*im3Cwc16X:'
  let pii_raw_values = [uname,password, global_client_resource_salt].join()
  let pii_hash = cryptojs.SHA3(pii_raw_values).toString()
  // console.log('pii hash', pii_hash)
  // console.log('\n')
  return pii_hash
}

const generateSecretShares = async () => {
  
  const protocolPrime = Buffer.from('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 'hex');
  
  // random keypair per client
  const keyServer1 = await ph.createCipher(protocolPrime); 
  const keyServer2 = await ph.createCipher(protocolPrime); 
  const keyServer3 = await ph.createCipher(protocolPrime); 
  const keyServer4 = await ph.createCipher(protocolPrime); 

  // client derives cipher from pii hash so its deterministic
  let piiHash = getPiiHash()
  if (piiHash.length % 2) {
    piiHash = '0' + piiHash;
  }
  let key = Buffer.from(piiHash, 'hex');
  let client = new ph.Cipher(protocolPrime, key)
  
  let C_piiHash =  client.encrypt(piiHash)
  // console.log('C_piiHash', C_piiHash)

  /// each key server returns enc(enc(hash, client), server)
  const K1_C_piiHash = keyServer1.encrypt(C_piiHash)
  const K2_C_piiHash = keyServer2.encrypt(C_piiHash)
  const K3_C_piiHash = keyServer3.encrypt(C_piiHash)
  const K4_C_piiHash = keyServer4.encrypt(C_piiHash)

  /// client decrypt each one
  const K1_piiHash = client.decrypt(K1_C_piiHash)
  const K2_piiHash = client.decrypt(K2_C_piiHash)
  const K3_piiHash = client.decrypt(K3_C_piiHash)
  const K4_piiHash = client.decrypt(K4_C_piiHash)

  /// length is 512 since its 2048 bits field
  const s1 = util.bufferToBigInt(K1_piiHash).toString(16)
  const s2 = util.bufferToBigInt(K2_piiHash).toString(16)
  const s3 = util.bufferToBigInt(K3_piiHash).toString(16)
  const s4 = util.bufferToBigInt(K4_piiHash).toString(16)

  return [s1, s2, s3, s4, client]
}

http.createServer(function (req, res) {
  
  (async () => {
    try {
        // when creating key we need all 4 key servers, but for recovery we need at least 2...
        var [_s1, _s2, _s3, _s4, client] = await generateSecretShares();

        var key = cryptojs.SHA3(_s1+_s2+_s3+_s4).toString()

        // split into 4 shares with a threshold of 2
        const numShares = 4
        const threshold = 2


        /// normalize shares function needed references secrets.share(...)...
        var shares = secrets.share(key, numShares, threshold)

        // 1 share is not enough!
        var comb = secrets.combine(shares.slice(0, 1))
        console.log(comb === key) // => false

        // combine 2 shares
        comb = secrets.combine(shares.slice(4, 9))
        console.log(comb === key) // => true

        // combine ALL shares
        comb = secrets.combine(shares)
        console.log(comb === key) // => true

    } catch (e) {
        
    }
  })();

  
  res.writeHead(200, {'Content-Type': 'text/plain'});
  // res.end('You should see two identical keys below, before and after share and combine.\n\n' + key + '\n' + comb);

}).listen(1337, '127.0.0.1');
console.log('Server running at http://127.0.0.1:1337/');
