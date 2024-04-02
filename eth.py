import os
import sys
import time
import requests
import mnemonic
import json
from eth_account import Account
from bip32utils import BIP32Key, BIP32_HARDEN
from web3 import Web3
from decimal import Decimal

zmok = 'https://api.zmok.io/mainnet/sfbitikqej2f0fzd'
contracts = {
	'eth': None,
	'vow': '0x1BBf25e71EC48B84d773809B4bA55B6F4bE946Fb',
	'vusd': '0x0fc6C0465C9739d4a42dAca22eB3b2CB0Eb9937A',
	'usdt': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
	'usdc': {
		'proxy': '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
		'impl': '0x0882477e7895bdC5cea7cB1552ed914aB157Fe56'
	},
	'tusd': {
		'proxy': '0x0000000000085d4780B73119b644AE5ecd22b376',
		'impl': '0xd6C03398c2113447d736C869A5C9118823cce9cA'
	}
}

_root_ = None

NOEXEC = os.environ.get('NOEXEC')
DEBUG = os.environ.get('DEBUG')
def debug(s):
	if DEBUG: print("> " + str(s), file=sys.stderr)

DP = os.environ.get('DP') or "m/44'/60'/0'/0/"
def path(x = 0, dp = None):
	if not x: x = 0
	if isinstance(x, int): x = str(x)
	if x.isnumeric(): x = (dp or DP) + x
	return x

def b2x(v):
	return '0x' + v.hex()

def x2b(v):
	return bytes.fromhex(v[2:] if v.startswith('0x') else v)

def hexprv(key):
	return b2x(key.PrivateKey())

def pk2addr(addr):
	return acct(addr) if len(addr) > 42 else addr

def acct(pk):
	acct = Account.from_key(pk.rstrip())
	return {
		'address': acct.address,
		'pk': pk,
		'acct': acct
	}

def child(key, path = ''):
	if type(key) == str:
		return acct(key)

	if type(key) == dict:
		if 'BIP32Key' in key:
			key = key['BIP32Key']
		else:
			return key

	if type(key) == dict: key = key['BIP32Key']
	for s in path.split("/"):
		if s == 'm' or s == '': continue
		i = int(s.rstrip("'"))  
		if "'" in s: i += BIP32_HARDEN
		key = key.ChildKey(i)

	pk = hexprv(key)
	a = Account.from_key(pk)
	ret = {
		'pk': pk,
		'acct': a,
		'address': a.address,
		'path': path,
		'BIP32Key': key,
		'xprv': key.ExtendedKey()
	}
	
	return ret

def key(secret):
	ret = secret
	if not secret: secret = os.environ.get("BIP39")
	if not secret: secret = os.environ.get("XPK")
	if not secret: sys.exit('No secret provided. Please set BIP39 or XPK')
	if type(secret) == str:
		if len(secret.strip().split(' ')) in [12,24]:
			eng = mnemonic.Mnemonic("english")
			seed = eng.to_seed(secret)
			ret = BIP32Key.fromEntropy(seed)
		elif secret.startswith('xpub') or secret.startswith('xprv'):
			ret = BIP32Key.fromExtendedKey(secret)
	elif type(secret) == BIP32Key:
		ret = secret
	elif type(secret) == dict:
		ret = secret['BIP32Key']

	# ret.dump()
	return ret

def node(DP = 0, secret = None):
	global _root_
	if secret or not _root_:
		_root_ = child(key(secret))
	return child(_root_, path(DP))

def abi(contract):
	key = 'Y7V344WF7CXFPUZIFB9P3Y5WV8W7IMZUMA'
	url = f'https://api.etherscan.io/api?module=contract&action=getabi&address={contract}&apikey={key}'
	res = requests.request("GET", url, headers={}, data={})
	
	global ABI
	ABI = res.json()
	if ABI['message'] != 'OK':
		raise Exception(ABI['result'])
	return ABI['result']

def contract(symbol = None):
	if not symbol: return None
	if symbol not in contracts:
		sys.exit('Contract symbol not supported!')

	global srv
	proxy = impl = contracts[symbol]
	if not proxy: return None
	if type(proxy) == dict:
		impl = proxy['impl']
		proxy = proxy['proxy']

	return srv.eth.contract(address=proxy, abi=abi(impl))

def srv(url = zmok):
	global srv
	srv = Web3(Web3.HTTPProvider(url))
	return srv

def txWait(id, sleep = 6, timeout = -1, msg = None):
	if not id:
		print(' - no transaction id provided!')
		return

	from web3.exceptions import TransactionNotFound
	from requests.exceptions import ChunkedEncodingError
	ret = None
	status = 'failed', 'success', 'timeout'

	while not ret:
		try:
			ret = srv.eth.get_transaction_receipt(id)
			break
		except TransactionNotFound as e:
			if not msg: msg = ' - waiting on tx...'
			print(msg, end = '', flush = True)
			msg = '.'
			timeout -= 1
			if timeout == 0:
				ret = {'status': -1}
				break
			time.sleep(sleep)
		except ChunkedEncodingError as e:
			time.sleep(sleep)

	if msg: print(' [' + status[ret['status']] + ']', flush = True)
	return ret

def txLogs(id, contract = 'vusd'):
	txr = srv.eth.get_transaction_receipt(id)
	from web3.logs import DISCARD, WARN, IGNORE
	ret =  contract.events.Transfer().process_receipt(txr, errors = WARN)
	return ret

def tryBalRaw(address, contract = None, sleep = 2, timeout = 5):
	# from web3.exceptions import BadFunctionCallOutput
	while True:
		try:
			if contract:
				return contract.functions.balanceOf(address).call()
			else:
				return srv.eth.get_balance(address)
		except Exception as e:
			debug(e)
			time.sleep(sleep)
			timeout -= 1
			if timeout == 0: raise e

def tryDecimals(contract, sleep = 2, timeout = 5):
	# from web3.exceptions import BadFunctionCallOutput
	while True:
		try:
			return contract.functions.decimals().call()
		except Exception as e:
			debug(e)
			time.sleep(sleep)
			timeout -= 1
			if timeout == 0: raise e
			
def balance(address, contract=None):
	if type(address) == dict: address = address['address']
	address = srv.to_checksum_address(address)

	bal = tryBalRaw(address, contract)
	if contract:
		decimals = tryDecimals(contract)
		if decimals < 0: raise Exception('Negative decimals!!')
		return Decimal(bal / 10 ** decimals)
	else:
		return Decimal(srv.from_wei(bal, 'ether'))

def waitBal(acct, contract, val = 0, sleep = 5):
	if type(acct) == dict: acct = acct['address']
	print(' - waiting for balance...', end = '')
	while balance(acct, contract) != val:
		print(f'bal: {balance(acct, contract)}')
		print('.', end = '', flush=True)
		time.sleep(sleep)
	print('.')

def topUp(to, amt, fuel = None, sleep = 6):
	if balance(to) >= amt:	# sufficient fuel in target account
		return True

	tx = sendFuel(to, amt, fuel)
	if not tx: return
	print(f' - fuel sent: {tx}')
	if NOEXEC: return True
	stat = txWait(tx, sleep, -1) # waits forever
	return tx if stat['status'] == 1 else None

def fuelPremium():
	premium = os.environ.get('ETHGAS') or "0%"
	return 1 + float(premium.replace('%', '')) / 100

def excJson(e):
	e = str(e).replace("'", '"')
	return json.loads(e) if is_json(e) else {'code': -1, 'message': e}

def sendFuel(to, amount: float = 0.0, acct = None):
	global _root_
	if not acct: acct = child(_root_, path(0))
	if balance(acct) < amount:
		print('Insufficient balance in fuel account!')
		return

	global srv
	if type(to) == dict: to = to['address']
	to = srv.to_checksum_address(to)
	if to == acct['address']:
		print('Same source and destination!')
		return

	gas = 21000
	gasPrice = int(srv.eth.gas_price * fuelPremium())
	if float(amount) == 0:
		amount = tryBalRaw(acct['address']) - gas * gasPrice
	else:
		amount = srv.to_wei(amount, 'ether')

	tx = {
		'to': to,
		'value': amount,
		'chainId': srv.eth.chain_id,
		'nonce': srv.eth.get_transaction_count(acct['address']),
		'gasPrice': gasPrice,
		'gas': gas
	}
	debug(tx)
	try:
		if NOEXEC: return True
		tx = srv.eth.account.sign_transaction(tx, x2b(acct['pk']))
		return srv.eth.send_raw_transaction(tx.rawTransaction).hex()
	except Exception as e:
		e = excJson(e)
		if e['code'] == -32000: # insufficient fuel
			print(' * sendFuel(): ' + e['message'])
			print(f' * {acct["path"]} {acct["address"]}: {balance(acct)} eth')
		else:
			print(' * sendFuel(): ' + str(e))

def send(to, contract = None, acct = None, amount = 0, hdr = False):
	if type(amount) == str: amount = Decimal(amount)
	if not contract:
		return sendFuel(to, amount, acct)

	global _root_, srv
	if not acct: acct = child(_root_, path(0))

	if amount == 0:
		amount = tryBalRaw(acct['address'], contract)
	else:
		decimals = tryDecimals(contract)
		amount = int(amount * 10 ** decimals)

	if type(to) == dict: to = to['address']
	to = srv.to_checksum_address(to)
	nonce = srv.eth.get_transaction_count(acct['address'])
	xfer = contract.functions.transfer(to, amount)
	tx = xfer.build_transaction({
		'chainId': srv.eth.chain_id,
		'from': acct['address'],
		'nonce': nonce,
		'gasPrice': int(srv.eth.gas_price * fuelPremium()),
		'gas': 100000
	})
	if hdr: print(f'[{amount}]: {acct["address"]} => {to}')
	debug(f'to: {to}, amount: {amount} ' + str(tx))

	# for gas, review:
	# https://ethereum.stackexchange.com/questions/110266/how-can-i-catch-error-eventerror-returned-error-insufficient-funds-for-gas

	try:
		if NOEXEC: return True
		tx = srv.eth.account.sign_transaction(tx, x2b(acct['pk']))
		return srv.eth.send_raw_transaction(tx.rawTransaction).hex()
	except ValueError as e:
		e = excJson(e)
		if e['code'] == -32000:
			print(' * send(): ' + e['message'] + f', gas price: {int(srv.eth.gas_price)}')
		else:
			raise e

def arg(n, v = '', msg = None):
	ret = sys.argv[n] if len(sys.argv) > n else v
	if msg and not ret: sys.exit(msg)
	return ret

def syntax(o):
	a,b = '<', '>'
	v = o['key']
	if 'def' in o:
		a,b = '[', ']'
		v += ' = ' + o['def']
	if 'env' in o:
		a,b = '[', ']'
		v += ' = $' + o['env']
	return a + v + b

def args(msgs, syntax):
	if len(sys.argv) == 1:
		if not syntax:
			s = ' '.join(map(syntax, msgs))
			syntax = '<list> | ' + sys.argv[0] + ' ' + s
		sys.exit(syntax)

	i = 1; ret = {}
	for m in msgs:
		v = ''
		if len(sys.argv) > i:
			v = sys.argv[i]
		if 'env' in m:
			v = os.environ.get(m['env'])
		if not v:
			if 'def' in m:
				v = m['def']
			else:
				msg = m['err'] if 'err' in m else m['key']
				sys.exit('\nNo ' + msg + ' provided!')
		ret[m['key']] = v
		i += 1
	return ret

def rng(s = ''):
	if '-' in s: 
		start, stop = s.split('-')
	else:
		start = stop = s or '0'
	return int(start or '0'), int(stop or '0')

def ctrlc():
	import signal
	def handler(sig, frame):
		sys.exit(0)
	signal.signal(signal.SIGINT, handler)

def is_json(myjson):
	try:
		json.loads(myjson)
	except ValueError as e:
		return False
	return True
