// INTERFACES
// ================================================================================================
import * as ph from '../index';
import { generateSafePrime } from '../util/primes';

// TEST RUNNER
// ================================================================================================
testCipher().then(() => { console.log('done!'); });

// TEST FUNCTIONS
// ================================================================================================
async function testCipher() {
    try {
        console.log('-'.repeat(100));
        let start = Date.now();
        const c1 = await ph.createCipher();
        console.log(`Created cipher in ${Date.now() - start} ms`);
        console.log(`Prime size: ${c1.prime.length * 8}, encryption key size: ${c1.enkey.length * 8}, decryption key size: ${c1.dekey.length * 8}`);

        // encrypt: data -> e1
        const data = 'Lorem Ipsum - это текст-"рыба", часто используемый в печати и вэб-дизайне. ';
        start = Date.now();
        const e1 = c1.encrypt(Buffer.from(data));
        console.log('-'.repeat(100));
        console.log(`Encrypted data in ${Date.now() - start} ms; e1 size is ${e1.length * 8} bits`);

        console.log('-'.repeat(100));
        // make sure e1 decrypts back to data
        start = Date.now();
        const d1 = c1.decrypt(e1);
        console.log(`Decrypted data in ${Date.now() - start} ms; success: ${d1.toString() === data}`);

        // encrypted: e1 -> e2
        const c2 = await ph.createCipher(c1.prime);
        start = Date.now();
        const e2 = c2.encrypt(e1);
        console.log(`Encrypted data in ${Date.now() - start} ms; e2 size is ${e2.length * 8} bits`);

        console.log('-'.repeat(100));
        // make sure e1 decypts back into e2
        start = Date.now();
        const d2 = c2.decrypt(e2);
        console.log(`Decrypted data in ${Date.now() - start} ms; success: ${d2.toString('hex') === e1.toString('hex')}`);

        console.log('-'.repeat(100));
        // create a cipher that has a merged key of first and second encryption
        const key12 = ph.mergeKeys(c1.enkey, c2.enkey);
        const c3 = new ph.Cipher(c1.prime, key12);
        console.log(`Prime size: ${c3.prime.length * 8}, encryption key size: ${c3.enkey.length * 8}, decryption key size: ${c3.dekey.length * 8}`);

        // decrypt e2 directly into data using the mereged key
        start = Date.now();
        const d12 = c3.decrypt(e2);
        console.log(`Decrypted data in ${Date.now() - start} ms; success: ${d12.toString() === data}`);
    } catch (e) {
        console.log(e)
    }
}

async function testPrimeGenerator() {
    try {
        console.log('-'.repeat(100));
        let start = Date.now();
        const p1 = await generateSafePrime(64);
        console.log(`Generated prime in ${Date.now() - start} ms; legnth ${p1.length * 8}`);

        console.log('-'.repeat(100));
        start = Date.now();
        const p2 = await generateSafePrime(512);
        console.log(`Generated prime in ${Date.now() - start} ms; legnth ${p2.length * 8}`);

        console.log('-'.repeat(100));
        start = Date.now();
        const p3 = await generateSafePrime(1024);
        console.log(`Generated prime in ${Date.now() - start} ms; legnth ${p3.length * 8}`);

        console.log('-'.repeat(100));
        start = Date.now();
        const p4 = await generateSafePrime(2048);
        console.log(`Generated prime in ${Date.now() - start} ms; legnth ${p4.length * 8}`);

    } catch (e) {
        console.log(e)
    }
}
