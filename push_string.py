#!/usr/bin/python3
from binascii import hexlify
import argparse

# Instantiate the parser
parser = argparse.ArgumentParser(description='This will output the instructions to push a string to the stack.')
parser.add_argument('-s', '--string', help='The string you would like to push.')

args = parser.parse_args()

_string = args.string

def string_to_stack(txt):
    chunkz = [txt[i:i+4] for i in range(0, len(txt), 4)]
    
    res = []

    for chunk in chunkz:
        ascii_output = hexlify(chunk.encode()).decode()
        if len(ascii_output) < 4:
            ascii_output = ascii_output#.ljust(8, '0')
        
        byte_res = "".join(reversed([ascii_output[i:i+2] for i in range(0, len(ascii_output), 2)]))
        if len(chunk) == 1:
            res.append("    \"   push  eax                       ;\",  #   " + chunk)
            res.append("    \"   mov   al,  0x" + byte_res + "                 ;\",  #   mov \'" + chunk + "\' into eax")
        elif len(chunk) == 2:
            res.append("    \"   push  eax                       ;\",  #   " + chunk)
            res.append("    \"   mov   ax,  0x" + byte_res + "               ;\",  #   mov \'" + chunk + "\' into eax")
        elif len(chunk) == 3:
            hex_value = int("0x" + byte_res, 16)
            neg_value = 0x100000000 - hex_value
            neg_hex = hex(neg_value)
            res.append("    \"   push  eax                       ;\",  #   " + chunk)
            res.append("    \"   neg  eax                        ;\",  #   " + chunk)
            res.append("    \".  mov eax, " + neg_hex + "             ;\",  #   negate value of " + chunk)
        else:
            res.append("    \"   push  0x" + byte_res + "                ;\",  #   " + chunk)
    
    res.reverse()
    for i in res:
        print(i)

string_to_stack(_string)