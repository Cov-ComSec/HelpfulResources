#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>

// 1. add to Additional include directories capstone include : /capstone/include
#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    /* 
    Disassembles the submitted shellcode. 
    This should assist players debugging errors such as bad addresses 
    or architecture changes that might not get caught by their assembler. 
    */
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("[ERROR] Disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |   Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            // Step through each instruction and map address
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        // Basically the same as previous section but don't try to print the correlating instruction
        printf("[ERROR] Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }
    cs_close(&handle);
}

void *shellcode_mem;
size_t shellcode_size;

int main(int argc, char **argv, char **envp)
{
    /*
    1. Print the intro jargon
    2. Read shellcode from stdin to stack
    3.  
    */
    
    // Unbuffer stdout... because thats a thing? 
    setvbuf(stdout,NULL,_IONBF,0);
    assert(argc > 0);

    puts("### Level 0\n");
    puts("Wellcome to shellcode level1.");
    puts("There are no protections on this level. Just read the flag at '/flag'\n");

    // Close other attack vectors
    for (int i = 3; i < 10000; i++) close(i);
    for (char **a = argv; *a != NULL; a++) memset(*a, 0, strlen(*a));
    for (char **a = envp; *a != NULL; a++) memset(*a, 0, strlen(*a));

    // Consider the start address of shellcode as a pointer
    shellcode_mem = mmap((void *) 0x1eb25000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);    
    assert(shellcode_mem == (void *) 0x1eb25000);
    printf("[INFO] Placing shellcode on the stack at %p!\n", shellcode_mem);
    puts("[INFO] ASLR is enabled, your shellcode should be position independant.\n");
    puts("\nReading 0x1000 bytes from stdin.\n");

    shellcode_size = read(0, shellcode_mem, 0x1000);
    assert(shellcode_size > 1 && "You're gonna need more shellcode than that :D"); 

    puts("\nThe challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode_mem, shellcode_size);
    puts("\n");

    puts("Executing shellcode!\n");
    ((void(*)())shellcode_mem)();
}