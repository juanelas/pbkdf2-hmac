import * as bigintConversion from 'bigint-conversion'

import { vectors } from '../test-vectors/pbkdf2'

describe('testing pbkdf2', function () {
  this.timeout(360000)
  for (const vector of vectors) {
    describe(`${vector.comment || ''} : ${JSON.stringify(vector.input)}`, function () { // eslint-disable-line
      if ('error' in vector) {
        it(`should be rejected because of ${vector.error?.toString() ?? 'unknown reason'}`, async function () {
          try {
            // @ts-expect-error
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
            ret = await _pkg(vector.input.P, vector.input.S, vector.input.c, vector.input.dkLen, vector.input.hash as _pkgTypes.HashAlg)
          }
          chai.expect(bigintConversion.bufToHex(ret)).to.equal(vector.output)
        })
      }
    })
  }
})
