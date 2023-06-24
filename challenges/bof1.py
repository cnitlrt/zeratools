#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
from pwn import *
#context.log_level = 'debug'
def exp():
    #context.terminal = ['tmux', 'splitw', '-h']
    #context.log_level = "debug"
    #attach(p)
    p.interactive()
if __name__ == "__main__":
    binary = './bof1'
    elf = ELF('./bof1')
    context.binary = binary
    libc = elf.libc
    if(len(sys.argv) == 3):
        p = remote(sys.argv[1],sys.argv[2])
    else:
        p = process(binary)
    l64 = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
    l32 = lambda      :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
    sla = lambda a,b  :p.sendlineafter(str(a),str(b))
    sa  = lambda a,b  :p.sendafter(str(a),str(b))
    lg  = lambda name,data : p.success(name + ": 0x%x" % data)
    se  = lambda payload: p.send(payload)
    rl  = lambda      : p.recv()
    sl  = lambda payload: p.sendline(payload)
    ru  = lambda a     :p.recvuntil(str(a))
    exp()
"""
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
"""
    
