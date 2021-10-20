.global _start
.intel_syntax noprefix

/* we will do 10 * 5 / 2 + 4 */
_start:
push 4
push 2
push 5
push 10

times:
/* 10 * 5 */
pop rdi
pop rsi
imul rdi, rsi

divide:
mov rax, rdi
pop rsi
div rsi

add:
pop rdx
add rax, rdx

exit:
mov rdi, rax 
mov rax, 60
syscall
