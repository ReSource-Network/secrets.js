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

  return [K1_piiHash, K2_piiHash, K3_piiHash, K4_piiHash, client]
}



http.createServer(function (req, res) {
  
  (async () => {
    try {
        var res = await generateSecretShares();
        console.log(res);
    } catch (e) {
        
    }
  })();

  const numShares = 4
  const threshold = 2

  var key, comb, shares, newShare;

  key = secrets.random(512);
  console.log('key', key)
  console.log('\n')
  
  shares = secrets.share(key, numShares, threshold);
  
  // shares [ '801e11032609e3a2ee5ce4465c2fd18e3bd80ee9128ea9195e550d47ee3f89b0783ae207e55d743848895969d7d455bc09a3443426fd153d40bd69242ee1ea0c087bebdc4984158b541bec539209da08a16',
  // '802df2064c021745cd78188ca99e730db6449487dffc547db0ea544abf405c48a3bd8d09f6e8e74110377bb7dc30affa9cd072f7fe206c4013a1749f688c6753afbcbe48cbbfe244db4b21f28772d16d9be',
  // '8033e3056a0bf4e72324fccaf5b1a2838d80e2ad2b22bfee157f63413f9a5f1f1530180c08cb992627a29a0d6a9c4688e0b160b9f994b42b9dea3009aaa8ecd6c2413d3b45160fbeee7b6a227b1b68fe82d',
  // '804a340c89d42e8b8b31f0d892fd360abcbc619b84c9bf647c552791cdae27a8d56342d40183c1a2608aee1a0a294aa7b6361f705e5b5f7b65888e283446bc2d30321561cfd9ddca043aab60ad950677ff3' ]
  
  console.log('shares', shares)
  
  comb = secrets.combine( shares );
  console.log('comb 1', comb)
  console.log('\n')

  // newShare = secrets.newShare(8, shares);
  // console.log('newShare', newShare)
  // console.log('\n')

  // comb = secrets.combine( shares.slice(1,threshold).concat(newShare) );
  // console.log('comb', comb)

  // console.log('\n')
  
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('You should see two identical keys below, before and after share and combine.\n\n' + key + '\n' + comb);

}).listen(1337, '127.0.0.1');
console.log('Server running at http://127.0.0.1:1337/');
