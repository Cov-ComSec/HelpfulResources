#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
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
    assert(argc > 0);
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stdin,NULL,_IONBF,0);

    printf("###\n");
    printf("### Welcome to shellcode level 3!\n", argv[0]);
    printf("###\n");
    printf("\n");

    for (int i = 3; i < 10000; i++) close(i);
    for (char **a = argv; *a != NULL; a++) memset(*a, 0, strlen(*a));
    for (char **a = envp; *a != NULL; a++) memset(*a, 0, strlen(*a));

    shellcode_mem = mmap((void *) 0x3067c000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    printf("[LEAK] Mapping shellcode memory at %p!\n", shellcode_mem);
    assert(shellcode_mem == (void *) 0x3067c000);

    puts("Reading 0x1000 bytes from stdin.\n");
    shellcode_size = read(0, shellcode_mem, 0x1000);
    assert(shellcode_size > 0);

    puts("This challenge requires that your shellcode does not have any `syscall`, 'sysenter', or `int` instructions. ");
    puts("System calls are too dangerous! This filter works by scanning through the shellcode for the following byte sequences: 0f05");
    puts("(`syscall`), 0f34 (`sysenter`), and 80cd (`int`). ");
    puts("[HINT] This check occurs on the data passed into the program\n");
    puts("[HINT] If only the shellcode at runtime could be different to the shellcode that is read in...\n");
    puts("[HINT] Self modifying shellcode may help you here\n");
    
    puts("[WARNING] The disassembler may break here\n");
    for (int i = 0; i < shellcode_size; i++)
    {
        uint16_t *scw = (uint16_t *)((uint8_t*)shellcode_mem + i);
        if (*scw == 0x80cd || *scw == 0x340f || *scw == 0x050f)
        {
            printf("Failed filter at byte %d!\n", i);
            exit(1);
        }
    }

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode_mem, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");
    ((void(*)())shellcode_mem)();
}