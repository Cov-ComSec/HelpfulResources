.global _start
.intel_syntax noprefix

_start:
push 4
push 11906
pop rax
pop rsi
div rsi 

test:
test al, 1
jnz odd

even:
div rsi
jmp test

odd:
mov rdi, rax
mov rax, 60
syscall
