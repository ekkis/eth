#!/usr/bin/env python

# moves tokens for a list of private keys piped in
# to successive addresses starting at a given offset
# of main wallet, using that wallet's fuel e.g.
#
#  cat pks |$0 vow 0
#  cat pks |$0

import re
import os
import sys
import eth
import time
import random

fuel = 0.01
ETHDELAYMAX = os.environ.get('ETHDELAYMAX')
if sys.stdin.isatty():
	sys.exit('Please pipe in a list of private keys e.g. `cat pks |$0 vow`')

opts = eth.args([
	{'key': 'curr', 'def': 'vow'},
	{'key': 'offset', 'def': '0'}
])

if not opts['offset'].isnumeric():
	sys.exit('Offset must be numeric!')
offset = int(opts['offset']) or 0

eth.srv()
contract = eth.contract(opts['curr'])
main = eth.node()
bal = eth.balance(main)
eth.debug(f'main: [{main["path"]}] {main["address"]} = {bal} ETH')
if bal == 0:
	sys.exit('No fuel in main account!')

for pk in sys.stdin:
	pk = pk.rstrip() # \n
	acct = eth.acct(pk)
	to = eth.node(offset, main)
	offset += 1

	bal = eth.balance(acct, contract)
	print(f'{pk}: {bal} -> {to["path"]}', flush=True)

	if bal > 0:
		if not eth.topUp(acct, fuel): continue
		tx = eth.send(to, contract, acct)
		print(f" - tokens sent: {tx}")
		res = eth.txWait(tx)
		if res['status'] == 0:
			continue

	if eth.balance(acct) > 0:
		tx = eth.sendFuel(to=main, acct=acct)
		print(f' - fuel returned: {tx}')

	if ETHDELAYMAX and bal > 0:
		sleep = random.randint(0, int(ETHDELAYMAX))
		print(f' - sleeping [{sleep} seconds]', flush=True)
		time.sleep(sleep)
