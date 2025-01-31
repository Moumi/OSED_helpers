#!/usr/bin/python3
import re
import sys
import argparse
from pathlib import Path


def auto_int(x):
	return int(x, 0)


# Instantiate the parser
parser = argparse.ArgumentParser(description='This automates the first part of module 10.4 OSED.')
parser.add_argument('--fname', help='The output file of rp++')
parser.add_argument('--outname', help='Output file of this program')
parser.add_argument('--base', help='Base address')
parser.add_argument('--ignore_ebp', action='store_true', help='Set if you want to see gadgets changing EBP')
parser.add_argument('--ignore_esp', action='store_true', help='Set if you want to see gadgets changing ESP')
parser.add_argument('--max_ret', type=auto_int, default=0x20, help='Maximum ret in bytes, default is 0x20')
parser.add_argument('--bad', help='List of bad characters space-separated (e.g 00 0a 0d)')

args = parser.parse_args()

fname = args.fname  # sys.argv[1] # File which contains rp++ output
outname = args.outname  # sys.argv[2] # File which will contain the new output
base = args.base
seperator = " | "  # Used when outputting gadgets
max_retn = args.max_ret  # # Highest value for a retn
ignore_ebp = args.ignore_ebp  # True # Don't allow gadgets which mess up ebp
ignore_esp = args.ignore_esp  # True # Don't allow gadgets which mess up ebp
bad = args.bad.split(" ")


def addr_has_bad_char(_addr):
	_addr_str = str(_addr.replace("0x", "").zfill(8))
	pairs_addr = [_addr_str[i:i + 2] for i in range(0, len(_addr_str), 2)]
	bc = False
	for bad_char in bad:
		if bad_char in pairs_addr:
			return True
	return False


def dedup_gadgets(all_gadgets):
	# using set
	visited = set()
	res = []

	# Iteration
	for a, b, c in all_gadgets:
		if not c in visited:
			visited.add(c)
			res.append((a, b, c))
	return res


all_gadgets = []

with open(fname, 'r') as f:
	for line in f.readlines():
		if not ";" in line:
			continue

		line = line.strip()
		addr = line[0:10]
		asm = " ".join(line.split(" ")[1:-2])
		_addr = hex(int(addr.replace("0x", ""), 16)) # - int(base, 16))

		if bad and addr_has_bad_char(_addr):
			continue

		all_gadgets.append((addr, _addr, asm))

# Removed duplicate gadgets
gadgets = dedup_gadgets(all_gadgets)
print("[+] Loaded %d gadgets..." % len(gadgets))

# List of all useful gadgets per register
general_regexes = {
	"Push-pop": r"push XXX .* pop e.. .*ret",
	"Pop": r"^pop XXX .*ret",
	"Inc": r"inc XXX .*ret",
	"Dec": r"dec XXX .*ret",
	"Neg": r"neg XXX .*ret",
	"Deref-from": r"mov e.., dword \[XXX(.*)\] .*ret",  # dereference value
	"Deref-to  ": r"mov XXX, dword \[e..(.*)\] .*ret",  # dereference value
	"Add": r"^add XXX, (e..|0x[0-9]{0,2}) .*ret",
	"Sub": r"^sub XXX, (e..|0x[0-9]{0,2}) .*ret",
	"Mov-from": r"mov e.., XXX .*ret",
	"Mov-to": r"mov XXX, e.. .*ret",
	"Write-from": r"mov dword \[e..(.*)\], XXX .*ret",
	"Write-to": r"mov dword \[XXX(.*)\], e.. .*ret",
	"Xchg": r"xchg (XXX, e..|XXX, eax) .*ret",
}
register_regexes = {
	"general": {"Xor": r"^xor e.., e.. .*ret",
				"Mov 0": r"^mov e.., 0 .*ret",
				"Pushad": r"pushad  ;",
				"Popad": r"popad  ;",
				},
	"esp": {"Mov-esp": r"mov e.., esp",  # mov esp into another register
			"Push-pop-esp": r"push esp.*pop e.*ret",  # push esp into another register
			},
	"eax": {},
	"ebx": {},
	"ecx": {},
	"edx": {},
	"edi": {},
	"esi": {},
}
# Fix the dicts
for register, register_regex in register_regexes.items():
	if register in ["eax", "ebx", "ecx", "edx", "edi", "esi"]:
		repl = general_regexes.copy()
		for k, v in repl.items():
			repl[k] = v.replace("XXX", register)
		register_regexes[register] = repl

# Prepare the results
gadget_results = {}
for k, v in register_regexes.items():
	gadget_results[k] = {}
	for k1, v1 in v.items():
		gadget_results[k][k1] = []

# This is the main part
for gadget_set in gadgets:
	gadget = gadget_set[2]
	for register, regex_dict in register_regexes.items():
		# print("[+] Checking for register:", register)
		for regex_type, regex in regex_dict.items():
			if re.search(regex, gadget):
				# Check for return value of bytes
				if "retn" in gadget:
					ret_value = re.search(r"retn (0x[A-Z0-9]+)", gadget)
					ret_value = ret_value.group(1)
					if int(ret_value, 16) > max_retn:
						continue

				# Ignore the gadgets which mess with ebp
				if ignore_ebp and "ebp" in gadget:
					continue

				# Ignore the gadgets which mess with esp
				if ignore_esp and "esp" in gadget:
					continue

				# Store the result
				gadget_results[register][regex_type].append(gadget_set)


# Sort the gadgets by length
def Sort_Tuple(tup):
	# getting length of list of tuples
	lst = len(tup)
	for i in range(0, lst):
		for j in range(0, lst - i - 1):
			if (len(tup[j][2]) > len(tup[j + 1][2])):
				temp = tup[j]
				tup[j] = tup[j + 1]
				tup[j + 1] = temp
	return tup


# Print results
def print_results(gadget_results):
	for k, v in gadget_results.items():
		for k1, v1 in v.items():
			x = Sort_Tuple(v1)
			if x != []:
				print("[+] " + k.upper() + " -> " + k1 + " (" + str(len(x)) + ")")
				print("__________________________")
				for tpl in x:
					print(" | ".join(tpl))
				print("-" * 100)
		print("=" * 100)


print_results(gadget_results)