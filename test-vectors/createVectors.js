const crypto = require('crypto')
const bigintConversion = require('bigint-conversion')

const dkLens = [64, 128, 256, 1024, 2048, 3072]
const algorithms = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']

const vectors = []
for (const dkLen of dkLens) {
  const P = crypto.randomBytes(Math.ceil(Math.random() * 768))
  const S = crypto.randomBytes(16)
  const c = Math.ceil(Math.random() * 512)
  for (const alg of algorithms) {
    const vector = {}
    const nodeAlg = alg.toLowerCase().replace('-', '')
    vector.input = { P: bigintConversion.bufToHex(P), S: bigintConversion.bufToHex(S), c, dkLen, hash: alg }
    vector.output = bigintConversion.bufToHex(crypto.pbkdf2Sync(P, S, c, dkLen, nodeAlg))
    vectors.push(vector)
  }
}

console.log(JSON.stringify(vectors).replace(/P":/g, 'P":bigintConversion.hexToBuf(')
  .replace(/","S":/g, '"),"S":bigintConversion.hexToBuf(')
  .replace(/","c":/g, '"),"c":'))
