/**
 * ID: 1044378
 * Assumes base virtual address: 0x555555554000 for PIEs.
 * Should work with both -pie & -no-pie programs just fine.
 * to run : $/.mdb ./executable
*/
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/user.h>
#include <syscall.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <capstone/capstone.h>

#define die(...)                      \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr);          \
        exit(EXIT_FAILURE);           \
    } while (0)

typedef struct
{
    int id;
    long address;
    long original_instruction;
    int enabled;
    char function_name[100];

} breakpoint;

breakpoint breakpoint_array[500];

int breakpoint_index = 0;
long base_address = 0;
int flag_program_is_being_run = 0;
Elf *elf;
csh handle;

Elf *load_file(char *filename)
{

    Elf *elf;
    Elf_Scn *symtab; /* To be used for printing the symbol table.  */

    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        die("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        die("(begin) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));

    int s_index = 0;
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));


        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab"))
            symtab = scn;
    }

    return elf;
}

Elf_Scn *locate_table_section(Elf *elf, int table_type)
{

    Elf_Scn *scn = NULL;
    Elf64_Shdr shdr;
    int found_symtab = 0;

    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        gelf_getshdr(scn, &shdr);

        if (shdr.sh_type == table_type)
        {
            /* found a symbol table */
            found_symtab = 1;
            break;
        }
    }

    if (!found_symtab)
    {
        printf("Symbol table not found.\n");
        exit(0);
    }

    return scn;
}


long initialise_load_address(Elf64_Ehdr *elf_hdr, pid_t pid) {
    //If this is a dynamic library (e.g. PIE)
    if (elf_hdr->e_type == ET_DYN) {
        return 0x555555554000;
    }
    return -1;

}


long get_symbol_address(char *symbol)
{

    int table_type = SHT_SYMTAB;
    Elf_Scn *scn = locate_table_section(elf, table_type);
    Elf64_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    Elf_Data *data;
    size_t shstrndx;
    size_t num_of_sections;
    int i, count = shdr.sh_size / shdr.sh_entsize;

    elf_getshdrstrndx(elf, &shstrndx);
    elf_getshdrnum(elf, &num_of_sections);
    data = elf_getdata(scn, NULL);

    for (i = 0; i < count; i++)
    {
        Elf64_Sym sym;
        gelf_getsym(data, i, &sym);
        Elf_Scn *current_section;
        Elf64_Shdr header;

        if (sym.st_shndx <= num_of_sections && sym.st_shndx > 0)
        {
            current_section = elf_getscn(elf, sym.st_shndx);
            gelf_getshdr(current_section, &header);
        }

        if (strcmp(elf_strptr(elf, shdr.sh_link, sym.st_name), symbol) == 0)
        {
            return (long)sym.st_value;
        }
    }

    return -1;
}

//disassemble 11 lines of code using capstone
void disas(const unsigned char *buffer, unsigned int size, long addr) {
	cs_insn *insn;
	size_t count;
    char current_line_index;

	count = cs_disasm(handle, buffer, size, addr, 11, &insn);
    
    if (count > 0) 
    {
		size_t j;
		for (j = 0; j < 11; j++) 
        {
            if(j==0)
            {
                current_line_index = '>';
            }
   
			fprintf(stderr, "%c  0x%"PRIx64":\t%s\t\t%s\n",current_line_index, insn[j].address - base_address, insn[j].mnemonic,
					insn[j].op_str);
            current_line_index = ' ';
            if(strcmp(insn[j].mnemonic,"retq")==0)      //stop at ret
            {
                break;
		    }
        }
		cs_free(insn, count);
	} 
    
    else
    {
        fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
    }
		

}

//get data buffer of text segment and send for disassembly
void disas_10_lines(long addr) {
    /* Loop over sections.  */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));
    
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));
        
        /* Locate .text  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".text")) {
            Elf_Data *data = NULL;
            size_t n = 0;
            
            long base_addr = shdr.sh_addr;
            long start_addr = get_symbol_address("_start") + base_address;

           // while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
                data = elf_getdata(scn, data);
                if(base_address == 0)
                    disas(data->d_buf+(addr-base_addr), data->d_size, addr);
                else
                    disas(data->d_buf+(addr-start_addr), data->d_size, addr);
                
                //disas(data->d_buf, data->d_size);
           // }
        }
    }
}

long process_inspect(int pid)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("(getregs) %s", strerror(errno));
    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0);

    return (long)regs.rip-1;        //for breakpoints regs.rip is equal to the address + 1 byte.
}

long set_breakpoint(int pid, long addr)
{
    /* Backup current code.  */
    long previous_code = 0;
    previous_code = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (previous_code == -1)
        die("(peekdata) %s", strerror(errno));

    /* Insert the breakpoint. */
    long trap = (previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
     if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1)
        die("(pokedata) %s", strerror(errno));

    previous_code = previous_code & 0xFF; //keep only first byte
    return previous_code;
}

void process_step(int pid)
{
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));
   

    waitpid(pid, 0, 0);    
}

void serve_breakpoint(int pid, long original_instruction, long addr)
{
    struct user_regs_struct regs;

     if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
         die("(getregs) %s", strerror(errno));

   long current_instruction = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL) & ~0xff;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)(current_instruction | original_instruction)) == -1)
        die("(pokedata) %s", strerror(errno));

}

//replaces a breakpoint with original instruction
void step_over_breakpoint(int pid, long original_instruction, long addr)
{
    struct user_regs_struct regs;

     if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
         die("(getregs) %s", strerror(errno));

    long current_instruction = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL) & ~0xff;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)(current_instruction | original_instruction)) == -1)
        die("(pokedata) %s", strerror(errno));
    regs.rip = addr;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));
}

void process_continue(int pid)
{
    
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1){
        printf("Program finished\n");
        exit(0);
        }
}

void list_breakpoints()
{
    int i;
    for(i = 0 ; i < breakpoint_index ; i++){
        if (breakpoint_array[i].enabled == 1)
        {
            printf("BREAKPOINT %-3d    ADR: 0x%-16lx    %s\n",i,breakpoint_array[i].address,breakpoint_array[i].function_name);
        }
    }
}

int search_for_breakpoint_at_addr(long addr)
{

    int i;
    for(i = 0 ; i < breakpoint_index; i++)
    {   
        if(breakpoint_array[i].address == addr )
            return i;
    }
    return -1;
}

void handleInput(char *input, int pid)
{
    // insert breakpoint
    if (input[0] == 'b' && input[1] == ' ' && input[2] == '*')
    {
        int i;
        char address_string[17];
        for (i = 0; i < 16 && (input[3 + i] != '\0' && input[3 + i] != ' ' && input[3 + i] != '\n'); i++)
        {
            address_string[i] = input[3 + i];
        }
        address_string[16] = '\0';

        long address_hex = strtol(address_string, NULL, 16) + base_address;

        breakpoint_array[breakpoint_index].address = address_hex ;
        breakpoint_array[breakpoint_index].enabled = 1;
        breakpoint_array[breakpoint_index].original_instruction = set_breakpoint(pid, address_hex);
        breakpoint_index++;
    }
    //insert breakpoint @ symbol
    else if (input[0] == 'b' && input[1] == ' ' && input[2] != '*')
    {
        int i, count = 0;
        char symbol_name[100];

        for (i = 0; i < 100 && (input[2 + i] != '\0' && input[2 + i] != ' ' && input[2 + i] != '\n'); i++)
        {
            symbol_name[i] = input[2 + i];
            count++;
        }
        symbol_name[count] = '\0';
        long address = get_symbol_address(symbol_name);


        if (address > 0)
        {
            address += base_address;  
            breakpoint_array[breakpoint_index].address = address;
            breakpoint_array[breakpoint_index].enabled = 1;
            breakpoint_array[breakpoint_index].original_instruction = set_breakpoint(pid, address);
            strcpy(breakpoint_array[breakpoint_index].function_name,symbol_name);
            breakpoint_index++;
        }
        else
        {
            printf("couldn't find symbol: %s\n", symbol_name);
        }
    }
    //list breakpoints
    else if (input[0] == 'l' && input[1] == '\n')
    {
        list_breakpoints();
        
    }
    //delete breakpoint 
    else if (input[0] == 'd' && input[1] == ' ')
    {
        int i, count = 0;
        char argument[4];
        for (i = 0; i < 3 && (input[2 + i] != '\0' && input[2 + i] != ' ' && input[2 + i] != '\n'); i++)
        {
            argument[i] = input[2 + i];
            count++;
        }
        argument[count] = '\0';
        int brpoint_number = atoi(argument);
        if (breakpoint_array[brpoint_number].enabled == 1)
        {
            breakpoint_array[brpoint_number].enabled = 0;
            serve_breakpoint(pid, breakpoint_array[brpoint_number].original_instruction, breakpoint_array[brpoint_number].address);
        }
        else
        {
            printf("Couldn't find breakpoint #%d\n",brpoint_number);
        }
    }
    //continue execution
    else if (input[0] == 'r' || input[0] == 'c' && input[1] == '\n')
    {

        if(flag_program_is_being_run == 0)
        {
            flag_program_is_being_run = 1;
        }
       
        long addr = process_inspect(pid);
        int brpoint_indx = search_for_breakpoint_at_addr(addr);
        if(brpoint_indx>-1)
        {  
            step_over_breakpoint(pid,breakpoint_array[brpoint_indx].original_instruction,addr);
            process_step(pid);
            set_breakpoint(pid,addr);
        }
        
        
        int status;
        process_continue(pid);
        waitpid(pid,&status,0);
       
        if (WIFEXITED(status))
        {
            printf("Program finished\n");
            exit(0);
        }

        if(input[0]=='r')
        {
            addr = process_inspect(pid);
            //printf("addr %lx\n",addr);
            disas_10_lines(addr);
        }
        
       

        
        
    }
    //step into
    else if (input[0] == 's' && input[1] == 'i' && input[2]=='\n')
    {
        if (flag_program_is_being_run == 1)
        {
            long current_address = process_inspect(pid) + 1;

            int brpoint_indx = search_for_breakpoint_at_addr(current_address); // check if it's a breakpoint
            if (brpoint_indx > -1)
            {
                    printf("it is\n");
                    step_over_breakpoint(pid, breakpoint_array[brpoint_indx].original_instruction, current_address);
                    process_step(pid);
                    set_breakpoint(pid, current_address);
                    disas_10_lines(process_inspect(pid) + 1);
            }
            else
            {
                    process_step(pid);
                    disas_10_lines(process_inspect(pid) + 1);
            }
        }

        else
        {
            printf("Program is not being run.\n");
        }
    }
    else if (input[0] == 'q' && input[1] == '\n')
    {
        printf("Exiting..\n");
        exit(0);
    }
    else
    {
        printf("unknown command!\n");
    }
}




int main(int argc, char *argv[])
{

    if (argc < 2)
        die("usage: elfloader <filename>");


    elf = load_file(argv[1]);

    // print_symbols(elf,SHT_SYMTAB);

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);


    pid_t pid = fork();

    switch (pid)
    {
    case -1: /* error */
        die("%s", strerror(errno));
    case 0: /* Code that is run by the child. */
        /* Start tracing.  */
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* execvp() is a system call, the child will block and
           the parent must do waitpid().
           The waitpid() of the parent is in the label
           waitpid_for_execvp.
         */
        execvp(argv[1], argv + 1);
        die("%s", strerror(errno));
    }

    /* Code that is run by the parent.  */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    //waitpid(pid, 0, 0);

    Elf64_Ehdr *hdr;
    hdr = elf64_getehdr(elf);
    long base = initialise_load_address(hdr,pid);
    if(base > 0)
    {
        base_address = base;
    }
    printf("pid: %d\n", pid);

    char input[100];
    do
    {
        printf("(mdb) ");
        fgets(input, sizeof(input), stdin);
        handleInput(input, pid);

    } while (1);

    cs_close(&handle);

    return 1;
}
