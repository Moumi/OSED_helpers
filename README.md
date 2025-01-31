# OSED_helpers
Helper scripts  that I have produced during the EXP-301 course of Offensive Security.

## shellcode_helper.py
This is, personally, my favourite creation. It helps you when you create a custom shellcode to identify where you have bad characters.

Works as follows:
```
python3 shellcode_helper.py -b "00 20"
```

## get_ropgadgets.py
Just some helper scripts to sort the output of rp++ and remove anything that has a bad character. Outputs a new file.

## wpm_helper.py
A script that can be run from WinDBG that will automatically generate the addresses of the code caves and for lpNumberOfBytesWritten. Just to ease the pain.

## compute_hash.py
Script that does the computation for the hashes, which will determine the ROR-key you should use based on the supplied bad characters list.

## push_string.py
Script that will give you the instructions needed to push a string onto a stack. No more hassle with figuring out the order, negating values or so.
Can be very handy for the shellcode_helper-script ;)