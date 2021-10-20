.global _start
.intel_syntax noprefix

/* we will do 4 ^ 3*/
_start:
xor rax, rax
mov rdi, 4
mov rsi, 4

loop:
cmp rax, 2
je done
imul rdi, rsi
inc rax
jmp loop

done:
mov rax, 60
syscall
