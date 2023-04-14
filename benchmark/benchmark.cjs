const pbkdf2 = require('#pkg')

const Benchmark = require('benchmark')

const unfilteredVectors = require('../test-vectors/pbkdf2.js').vectors

const vectors = unfilteredVectors.filter(val => !('error' in val))

const suite = new Benchmark.Suite('PBKDF2')
for (const vector of vectors) {
  // add tests
  suite.add(`${vector.comment ?? ''}: ${JSON.stringify(vector.input)} `, {
    defer: true,
    fn: function (deferred) {
      pbkdf2(vector.input.P, vector.input.S, vector.input.c, vector.input.dkLen).then(() => deferred.resolve()).catch((reason) => console.error)
    }
  })
}
// add listeners
suite.on('cycle', function (event) {
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
