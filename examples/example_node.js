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
        var [_s1, _s2, _s3, _s4, client] = await generateSecretShares();

        const numShares = 4
        const threshold = 2

        var key, comb, _shares, newShare;

        /// Instead of generating a key, we assume we have shares to create a unique threshold polynomial
        // key = secrets.random(512);
        // console.log('key', key)
        // console.log('\n')        
        // shares = secrets.share(key, numShares, threshold);

        /// share length is 512 bit with length of 128 hex elements in example, but we pass in 2048 bit with length of 512 hex elements here
        /// we prepend hex 8 which is backspace followed by the share number (impl detail in secrets library) 
        // var shares = ['801' + s1, '802' + s2, '803' +s3, '804' + s4]
        
        // precomputed from generateSecretShares() and copied here as a literal...
        // this generates a new k1-4 key so copying shares returned here from single execution to get determinism
        let shares = [ '801d7876ef69a390e0b109e73e22349f9868e8e6bf23aed4c9d98a43515a1cba120a0a008dafdfb5fef442d5d1b6097e4ba52151c699bed4e3b11c67f736d56bcf47aba0db9449cb173cc1211c2a11fc7f0f58f60e32c6fc597598b7466065da701ff4538ac64d66443d3bbe768967cd3542b9a5095e8388bb7613d710067cb6ffd87c44e36eb2914f332672557238c0bf6c7c4bb46be935031ebffdaff0dd36088a5720529209795a02bd62e4c71bdbb79dfaa5135dfe064c96c55c4991adfbce127e1a9550bbdf8975bbf2d8a1ab121ec72cd0d76c2aa7cbc198da088616b238743981332ede8627648db859439a3e634c64442b53b67aaa3cd98648627df99bb',
        '802796fcb2845a79064e025b1023bd8a2512a15c51fa73c5b013eb4744b8ab47a81a0eabd1852a0d4654eda0a34d93045a754d3a7632090c07a20f7a8ab8cab8273ab3e354006f3df0168663ee1d429d86452ac81715f339e0e1b497fac170335b2e6abbfc6409c96f05154110df731959fc5b4b58fe89dcce3c52dc44e9751dfbfb445cf72a3daa1032d16498382d18da6da7223f4c9eaa9d117f61825c03d1f042426c9fee2d8afaa29d94f92df82132f06493a0be6400dfa828ff1af6d2f8183bff271260b7b1782d6181b42128064d8f2239349bf931858b8cbcf4d5d187d9439ec13ebbbf3434618e28fb80399bac2f60c49283f710ca64179d0d13ba2f849',
        '803e8b6fde04d2ac85f3bd80f143da157494e02f73b054e2270a391633544c5547783e915d656307087efeddb24f164697249f113405429bd69979fdc9c6921fcbee2094ed26b17f21da04fd522470114801d5eb0caff4cd8697d636020a3558f8d8030cb65760d0e550d76990b9cc984f2acc9486d9c5d2ba5cb4a86a8470e9dd4a6b37f9a1127c339b79131d7ecdb6a85988a5648358f8dc93c97e903b9950fcb1b612adf370cb8e847114a6b7d8b69fbbe08982bd4e557154f73967d1f61194f0b0811b6208bae89ad05d0451f28a34ebda1e3e20e9f24bd3f1e5a8f8fb72824d517964f9f06c73a73bac98b6810d6a84d7986c65433e7a93837366dab253a5b',
        '804caff3a2ae292516eca633936c40eb9b247523203c55fde4e78ae4726f953fdd8d4ef8f9cf5f87edf0143a4967721116f101201f16c178ac8b6992dfdd3352ee2671d6645e6cabdccfca78aaa510ec0cda815f03d3aa9f5d18554450de7195c517bf563c71b678916ac74890c58954f1a9f4dd945881c8b6266c883bb875892bb144e946d14156bfda1cbacdc03a16e16de6c3d32dfaca2eecded4070446e3450225e74df84fa1a54f6322ffb0dfac37cd2110b2d99caa0415081a7180df3591f4b4bfa1e05848e93da10f3646e5760ba9d94561f9ca865c15e3df0c9e15d0171505fce3b640cfa36f2b7c319688e8d823b4110a9d2f2c26b89fed776c61a1aa6' ]
  
        
        // todo: transform preComputedShares / sharesSeed above into real SSS shares

        // example of how shares looked in unmodified example_node.js script
        // shares [ '801e11032609e3a2ee5ce4465c2fd18e3bd80ee9128ea9195e550d47ee3f89b0783ae207e55d743848895969d7d455bc09a3443426fd153d40bd69242ee1ea0c087bebdc4984158b541bec539209da08a16',
        // '802df2064c021745cd78188ca99e730db6449487dffc547db0ea544abf405c48a3bd8d09f6e8e74110377bb7dc30affa9cd072f7fe206c4013a1749f688c6753afbcbe48cbbfe244db4b21f28772d16d9be',
        // '8033e3056a0bf4e72324fccaf5b1a2838d80e2ad2b22bfee157f63413f9a5f1f1530180c08cb992627a29a0d6a9c4688e0b160b9f994b42b9dea3009aaa8ecd6c2413d3b45160fbeee7b6a227b1b68fe82d',
        // '804a340c89d42e8b8b31f0d892fd360abcbc619b84c9bf647c552791cdae27a8d56342d40183c1a2608aee1a0a294aa7b6361f705e5b5f7b65888e283446bc2d30321561cfd9ddca043aab60ad950677ff3' ]
        
        console.log('shares', shares)
        
        comb = secrets.combine( shares );
        console.log('comb 1', comb)
        console.log('\n')

        // newShare = secrets.newShare(2, shares);
        // // console.log('newShare', newShare)
        // // console.log('\n')

        // comb = secrets.combine( shares.slice(2,threshold).concat(newShare) );
        // console.log('comb 2', comb)

        // console.log('\n')
    } catch (e) {
        
    }
  })();

  
  res.writeHead(200, {'Content-Type': 'text/plain'});
  // res.end('You should see two identical keys below, before and after share and combine.\n\n' + key + '\n' + comb);

}).listen(1337, '127.0.0.1');
console.log('Server running at http://127.0.0.1:1337/');
