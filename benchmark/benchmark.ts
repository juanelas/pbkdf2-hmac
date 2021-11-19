import pbkdf2 from '..'

import Benchmark from 'benchmark'

import { vectors as unfilteredVectors } from '../test-vectors/pbkdf2'

const vectors = unfilteredVectors.filter(val => !('error' in val))

const suite = new Benchmark.Suite('PBKDF2')
for (const vector of vectors) {
  // add tests
  suite.add(`${vector.comment ?? ''}: ${JSON.stringify(vector.input)} `, {
    defer: true,
    fn: function (deferred: any) {
      pbkdf2(vector.input.P as any, vector.input.S as any, vector.input.c, vector.input.dkLen).then(() => deferred.resolve()).catch((reason) => console.error)
    }
  })
}
// add listeners
suite.on('cycle', function (event: any) {
  console.log(String(event.target))
})
  .on('start', function () {
    console.log('Starting benchmarks for PBKDF2... (keep calm)')
  })
  .on('complete', function () {
    console.log('Benchmark completed')
  })
// run
  .run()
