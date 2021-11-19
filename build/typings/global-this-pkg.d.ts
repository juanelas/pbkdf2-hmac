import * as _pkgModule from '../..'

declare global {
  const _pkg: typeof _pkgModule.default extends Function ? typeof _pkgModule.default : typeof _pkgModule
}

export as namespace _pkgTypes
export = _pkgModule
