from pwn import *

context.arch = "amd64"
#context.log_level = debug

def print_clean(data):
    data = data.split(b"\n")
    for i in data:
        print(i.decode("latin-1"))

# shellcode goes here
shellcode = asm(f"""

""")

p = remote("127.0.0.1", 1337)
print_clean(p.recvuntil(b"Reading 0x1000 bytes from stdin.\n"))
p.sendline(shellcode)
print_clean(p.readrepeat())
