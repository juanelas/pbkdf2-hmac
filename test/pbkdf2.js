// Every test file (you can create as many as you want) should start like this
// Please, do NOT touch. They will be automatically removed for browser tests -->
const _pkg = require('../lib/index.node')
const chai = require('chai')
// <--

const bigintConversion = require('bigint-conversion')

const vectors = require('./vectors/pbkdf2')

describe('testing pbkdf2', function () {
  this.timeout(360000)
  for (const vector of vectors) {
    describe(`${vector.comment} : ${JSON.stringify(vector.input)}`, function () {
      if ('error' in vector) {
        it(`should be rejected because of ${vector.error}`, async function () {
          try {
            await _pkg(vector.input.P, vector.input.S, vector.input.c, vector.input.dkLen, vector.input.hash)
            throw new Error('should have failed')
          } catch (err) {
            chai.expect(err).to.be.instanceOf(vector.error)
          }
        })
      } else {
        it(`should match ${vector.output}`, async function () {
          let ret
          if (vector.input.hash === 'SHA-256') { // Let's call with the default value
            ret = await _pkg(vector.input.P, vector.input.S, vector.input.c, vector.input.dkLen)
          } else {
            ret = await _pkg(vector.input.P, vector.input.S, vector.input.c, vector.input.dkLen, vector.input.hash)
          }
          chai.expect(bigintConversion.bufToHex(ret)).to.equal(vector.output)
        })
      }
    })
  }
})
