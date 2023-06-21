const Wallet = require('ethereumjs-wallet');
const EthUtil = require('ethereumjs-util')

const pk = '0xb3831f01815f3f15f1db203b480ec1fb93d62781b6641390fa4db00d9d3693f4'

const getMethods = (obj) => {
  let properties = new Set()
  let currentObj = obj
  do {
    Object.getOwnPropertyNames(currentObj).map(item => properties.add(item))
  } while ((currentObj = Object.getPrototypeOf(currentObj)))
  return [...properties.keys()].filter(item => typeof obj[item] === 'function')
}

const pkbuf = EthUtil.toBuffer(pk)
// console.log(pkbuf)
const w = Wallet['default'].fromPrivateKey(pkbuf)
// console.log(w.getAddressString())

// const hd = new Wallet.hdkey(pk)
const hd = new Wallet.hdkey(w)
console.log(hd)
console.log(hd.privateExtendedKey())
console.log(hd.publicExtendedKey())
