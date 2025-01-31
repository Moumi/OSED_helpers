#!/usr/bin/python3
import numpy, sys
import argparse

parser = argparse.ArgumentParser(description="Compute hashes with a specific ror-key.")
parser.add_argument("-r", help="Ror byte specified")
parser.add_argument(
        "-b",
        "--bad-chars",
        help="space separated list of bad chars to check for in final egghunter (default: 00)",
        default=["00"],
        nargs="+",
    )

args = parser.parse_args()

libraries = ["TerminateProcess", "LoadLibraryA", "CreateProcessA"]

def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))
    
def is_valid_hashes(hashes):
    for h in hashes:
        vals = [h[i:i+2] for i in range(0, len(h), 2)][-4:]
        for bc in args.bad_chars:
            if bc in vals:
                return False
    return True

if __name__ == '__main__':
    # Initialize variables
    valid_bytes = []
    start_range = 10
    end_range = 255
    if args.r is not None:
        start_range = int(args.r, 16)
        end_range = start_range + 1
    
    for ror_byte in range(start_range, end_range):
        if "{0:02x}".format(ror_byte) in args.bad_chars:
            continue
        res = []
        for library in libraries:
            ror_count = 0
            edx = 0x00
            for eax in library:
                edx = edx + ord(eax)
                if ror_count < len(library)-1:
                    edx = ror_str(edx, ror_byte)
                ror_count += 1

            res.append(hex(edx))
        if is_valid_hashes(res):
            valid_bytes.append(hex(ror_byte))

            print("[+] ROR byte: " + str(hex(ror_byte)))
            for i in range(len(libraries)):
                tabs = 3 - (len(libraries[i]) // 8)
                print(libraries[i] + ("\t"*tabs) + " -> " + res[i])
            break
        else:
            if args.r is not None:
                print("[!] Note, you supplied a ror-key which results in bad characters. Run again without the -r option!")