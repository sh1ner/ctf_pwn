// gcc -o pwn pwn.c
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"
#include "fcntl.h"
#include "time.h"

char dirname[0x10];

char buf[0x1000];
char flag[0x100];
char rust_main[0x1000];

void init() {
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 1, 0);
	setvbuf(stderr, 0, 1, 0);
	srand(time(NULL));
	for (int i = 0; i < 0x10; ++i) {
		dirname[i] = rand() % 10 + '0';
	}
	dirname[0x10 - 1] = 0;

	char cmd[0x100] = "cp -r /pwn/ /tmp/";
	strcat(cmd, dirname);
	system(cmd);

	strcpy(cmd, "/tmp/");
	strcat(cmd, dirname);
	chdir(cmd);

	close(2);

	alarm(10);
}

void clean() {
	char cmd[0x100] = "rm -rf /tmp/";
	strcat(cmd, dirname);
	system(cmd);
}

void pwn(){
	printf("Got a thought?\n");
	read(0, buf, 0x1000);
	printf("Let\'s see..\n");

	if (strstr(buf, "mangle") != NULL) {
		puts("Don't try to mangle!");
		return;
	}

	if (strstr(buf, "extern") != NULL) {
		puts("I hate them, please use Rust 2018!");
		return;
	}

	if (strstr(buf, "std") != NULL) {
		puts("Why do you want std library?");
		return;
	}

	if (strstr(buf, "io") != NULL) {
		puts("Oops, No IO");
		return;
	}

	if (strstr(buf, "unsafe") != NULL) {
		puts("Rust should be safe");
		return;
	}

	if (strstr(buf, "#") != NULL) {
		puts("Please don't mess up my system");
		return;
	}

	if (strstr(buf, "macro") != NULL) {
		puts("Macro is good, but not here");
		return;
	}

	if (strstr(buf, "use") != NULL) {
		puts("Don't try to use me you little..");
		return;
	}

	// prepare flag
	int flag_fd = open("/flag", O_RDONLY);
	read(flag_fd, flag, 0x100);
	close(flag_fd);

	int main_code = open("./src/main.rs.tpl", O_RDONLY);
	read(main_code, rust_main, 0x1000);
	close(main_code);

	main_code = open("./src/main.rs", O_RDWR | O_CREAT, 0777);

	char *flag_start = strstr(rust_main, "{}");
	for (char *ch = (char*)rust_main; ch < strlen(rust_main) + rust_main; ch ++) {
		if (ch == flag_start) {
			write(main_code, "\"", 1);
			for (char *flag_ch = (char*)flag; flag_ch < strlen(flag) + flag; flag_ch ++) {
				write(main_code, flag_ch, 1);
			}

			ch ++; // jump over '}'
			write(main_code, "\"", 1);
		} else {
			write(main_code, ch, 1);
		}
	}

	close(main_code);

	int fd = open("./lib/code/src/lib.rs", O_RDWR | O_CREAT, 0777);
	write(fd, buf, strlen(buf) - 1);
	close(fd);

	system("RUSTFLAGS=\"-F unsafe-code\" cargo +$VERSION build -p code && cargo +$VERSION run");
}

int main(int argc, char const *argv[],char const *env[])
{
	init();
	pwn();
	clean();
	return 0;
}

