#!/usr/bin/python3
import ctypes, struct
from keystone import *
import argparse
from struct import unpack, pack
import sys

parser = argparse.ArgumentParser(description="Creates custom shellcode showing bad chars")
parser.add_argument(
        "-b",
        "--bad-chars",
        help="space separated list of bad chars to check for in final egghunter (default: 00)",
        default=["00"],
        nargs="+",
    )
parser.add_argument("--debug", action="store_true", help="Debug in Windbg")

args = parser.parse_args()

debugWindbg = False
if args.debug:
    debugWindbg = args.debug

# Helper function to port an ip address to a value for your shellcode
def convertIP(ipaddress):
    octets = ipaddress.split(".")
    newoctets = []
    for octet in reversed(octets):
        newoctets.append(f'{int(octet):x}')
    newoctets = "0x" + "".join(newoctets)
    return newoctets

# Helper function to port a port number to a value for your shellcode
def convertPort(port):
    port = ((port << 8) | (port >> 8)) & 0xFFFF
    port_nr = (port << 8)
    res = (port_nr << 8)
    res += 2
    inverse = int("0xffffffff", 16) + 1 - int(hex(res), 16)
    return f'0x{inverse:x}'

# Insert your x86 assembly code here.
CODE = [
]

# cancel SGR codes if we don't write to a terminal
if not __import__("sys").stdout.isatty():
    for _ in dir():
        if isinstance(_, str) and _[0] != "_":
            locals()[_] = ""
else:
    # set Windows console in VT mode
    if __import__("platform").system() == "Windows":
        kernel32 = __import__("ctypes").windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        del kernel32
ENDC    	=  '\033[m' # reset to the defaults
TGREEN  	=  '\033[32m' # Green Text
TRED    	=  '\033[31m' # Red Text
TYELLOW 	=  '\033[33m' # Yellow text
TMAGENTA	=  '\033[35m' # Yellow text
TAB     	=  '\t'       # TAB

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)

asm_code = CODE

for shellcode_line in asm_code:
    if ";" not in shellcode_line:
        print(TYELLOW + shellcode_line.strip(), ENDC, end="\n", sep="")
    else:
        try:
            encoding, count = ks.asm(shellcode_line)
            print(TAB, end="", sep="")
            byte_length = 0
            for e in encoding:
                sh = struct.pack("B", e)
                final = "\\x{0:02x}".format(e)
                byte_length += len(final)
                if "{0:02x}".format(e) in args.bad_chars:
                    print(TRED + final, ENDC, end="", sep="")
                else:
                    print(TGREEN + final, ENDC, end="", sep="")
                    
            tabs = 4 - (byte_length // 8)
            print(("\t" * tabs) + shellcode_line.strip(), ENDC, end="", sep="")
            print()
        except Exception as e:
            print(TMAGENTA + TAB + shellcode_line.strip(), ENDC, end="\n", sep="")
print()

encoding, count = ks.asm("\n".join(asm_code))
print("Encoded %d instructions..." % count)
final_shellcode = ""
found_bad_chars = False
for e in encoding:
    final = "\\x{0:02x}".format(e)
    final_shellcode += final
    if "{0:02x}".format(e) in args.bad_chars:
        print(TRED + final, ENDC, end="", sep="")
        found_bad_chars = True
    else:
        print(TGREEN + final, ENDC, end="", sep="")

print("\n")

if found_bad_chars:
    print(TRED + "[+] There are bad characters in the shellcode, go fix!", ENDC)
else:
    print("Size of shellcode: %d bytes" % (len(final_shellcode) / 4))
    print("--------------------------------")
    print("IP used   \t%s" % (ipaddress))
    print("Port used \t%s" % (port))


if debugWindbg:
    sh = b""
    ENDC = '\033[m' # reset to the defaults
    TGREEN =  '\033[32m' # Green Text
    TRED   =  '\033[31m' # Red Text
    for e in encoding:
        sh += struct.pack("B", e)

    shellcode = bytearray(sh)


    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                              ctypes.c_int(len(shellcode)),
                                              ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                         buf,
                                         ctypes.c_int(len(shellcode)))

    print("Shellcode located at address %s" % hex(ptr))
    print("Shellcode length: " + str(len(shellcode)))
    input("...ENTER TO EXECUTE SHELLCODE...")

    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.c_int(ptr),
                                             ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.pointer(ctypes.c_int(0)))

    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

