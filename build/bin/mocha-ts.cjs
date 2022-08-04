#! /usr/bin/env node
const fs = require('fs')
const path = require('path')
const childProcess = require('child_process')
const glob = require('glob')
const minimatch = require('minimatch')
const rimraf = require('rimraf')

const rootDir = path.join(__dirname, '../..')

const pkgJson = require(path.join(rootDir, 'package.json'))

const mochaTsRelativeDir = pkgJson.directories['mocha-ts']
const mochaTsDir = path.join(rootDir, mochaTsRelativeDir)

// clean .mocha-ts directory
rimraf.sync(mochaTsDir)

const semaphorePath = `${mochaTsRelativeDir}/semaphore`

const tempDir = mochaTsDir

let commonjs = false
let watch = false
const testFiles = []

// First let us prepare the args to pass to mocha.
// ts.files will be replaced by their js-transpiled counterparts
// a watch file to our semaphore will be added
const processedArgs = processArgs(process.argv.slice(2))

commonjs = watch ? true : commonjs // mocha in watch mode only supports commonjs

if (commonjs) {
  // we create a new package.json with 'type: "module"' removed
  const tempPkgJsonPath = path.join(tempDir, 'package.json')

  delete pkgJson.type

  fs.mkdirSync(tempDir, { recursive: true })
  fs.writeFileSync(tempPkgJsonPath, JSON.stringify(pkgJson, undefined, 2), { encoding: 'utf-8' })

  console.log('\x1b[33mℹ [mocha-ts] Running tests against the CommonJS module \x1b[0m')
} else {
  console.log('\x1b[33mℹ [mocha-ts] Running tests against the ESM module \x1b[0m')
}
console.log()

const rollupBuilder = require('../testing/mocha/builders/RollupBuilder.cjs').rollupBuilder

rollupBuilder.start({ commonjs, watch: false }).then(() => {
  rollupBuilder.close()
  const testsBuilder = require('../testing/mocha/builders/TestsBuilder.cjs').testBuilder
  testsBuilder.start({ commonjs, testFiles }).then(() => {
    testsBuilder.close()
    // Let us write a file with the test files for the child process to get them
    fs.writeFileSync(path.join(tempDir, 'testSetup.json'), JSON.stringify({ testFiles, commonjs }), { encoding: 'utf-8' })
    // Now we can run a script and invoke a callback when complete, e.g.
    runScript(path.join(rootDir, 'node_modules/mocha/bin/mocha'), processedArgs)
  })
})

function processArgs (args) {
  args = process.argv.slice(2).map(arg => {
    // Let us first remove surrounding quotes in string (it gives issues in windows)
    arg = arg.replace(/^['"]/, '').replace(/['"]$/, '')
    const filenames = glob.sync(arg, { cwd: rootDir, matchBase: true })
    if (filenames.length > 0) {
      return filenames.map(file => {
        const isTsTestFile = minimatch(file, '{test/**/*.ts,src/**/*.spec.ts}', { matchBase: true })
        if (isTsTestFile) {
          testFiles.push(file)
          return `${mochaTsRelativeDir}/${file.slice(0, -3)}.js`
        }
        return file
      })
    }
    return arg
  })

  const processedArgs = []

  for (const arg of args) {
    if (Array.isArray(arg)) {
      processedArgs.push(...arg)
    } else {
      if (arg === '--commonjs' || arg === '--cjs') {
        commonjs = true
      }
      if (arg !== '--watch-files') {
        processedArgs.push(arg)
      }
      if (arg === '--watch' || arg === '-w') {
        watch = true
        processedArgs.push('--watch-files')
        processedArgs.push(semaphorePath)
      }
    }
  }

  return processedArgs
}

function runScript (scriptPath, args) {
  const mochaCmd = childProcess.fork(scriptPath, args, {
    cwd: rootDir
  })

  mochaCmd.on('error', (error) => {
    throw error
  })

  // execute the callback once the process has finished running
  mochaCmd.on('exit', function (code) {
    if (code !== 0) {
      throw new Error('exit code ' + code)
    }
  })
}
