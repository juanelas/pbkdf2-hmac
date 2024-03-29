import * as bigintConversion from 'bigint-conversion'
import scrypt, { HashAlg } from '#pkg'
import { vectors } from '../test-vectors/pbkdf2'

describe('testing pbkdf2', function () {
  this.timeout(360000)

  for (const vector of vectors) {
    describe(`${vector.comment ?? ''} : ${JSON.stringify(vector.input)}`, function () {
      if ('error' in vector) {
        it(`should be rejected because of ${vector.error !== undefined ? vector.error.toString() : 'unknown reason'}`, async function () {
          try {
            // @ts-expect-error
            await scrypt(vector.input.P, vector.input.S, vector.input.c, vector.input.dkLen, vector.input.hash)
            throw new Error('should have failed')
          } catch (err) {
            chai.expect(err).to.be.instanceOf(vector.error)
          }
        })
      } else {
        it(`should match ${vector.output}`, async function () {
          let ret
          if (vector.input.hash === 'SHA-256') { // Let's call with the default value
            ret = await scrypt(vector.input.P, vector.input.S, vector.input.c, vector.input.dkLen)
          } else {
            ret = await scrypt(vector.input.P, vector.input.S, vector.input.c, vector.input.dkLen, vector.input.hash as HashAlg)
          }
          chai.expect(bigintConversion.bufToHex(ret)).to.equal(vector.output)
        })
      }
    })
  }
})
