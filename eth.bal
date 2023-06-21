#!/usr/bin/env python

# this script generates balances for a list of addresses or private keys
# piped in e.g.
#
#   cat mylist.txt |$0 vow
#
# or by exploring all the derivation paths, given a secret. the script
# can be bracketed in the following form:
#
#	export BIP39=...
#   $0 vow 10-20 -z
#
# offsets may be passed in the forms: m, m-n, m- and -n
# the form m- stops on a zero balance.  the -z parameter
# may be passed to suppress zero-balance listings
#
# it can also be used to query a single address:
#
# $0 0x... vow

import os
import sys
import eth

n = 1
addr = None
eth.ctrlc()
srv = eth.srv()
sym = eth.arg(n, 'eth'); n+=1
if sym.startswith('0x'):
	addr = sym
	sym = eth.arg(n, 'eth')
if addr:
	for sym in sym.split('/'):
		print(f'{eth.balance(eth.pk2addr(addr), eth.contract(sym))} {sym}')
	sys.exit()

tot = 0
contract = eth.contract(sym)
if not sys.stdin.isatty():
	for addr in sys.stdin:
		addr = addr.rstrip()
		if addr == '': continue
		bal = eth.balance(eth.pk2addr(addr), contract)
			
		tot += bal
		print(f'{addr}\t{round(bal, 0)}\t{tot}')

	print(f'total={tot}')
	sys.exit()

i, stop = eth.rng(eth.arg(2))
nz = eth.arg(3)
while True:
	n = eth.node(i)
	bal = eth.balance(n, contract)
	tot += bal
	i += 1
	if stop == 0 and bal <= 0:
		break
	if nz != '-z' or bal > 0:
		print(f'{n["path"]} {n["address"]} {bal} {sym}')
	if i > stop and stop > 0:
		break

print(f'total={tot}')
