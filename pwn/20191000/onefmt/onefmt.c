// gcc onefmt.c -fstack-protector -z noexecstack -fpie -no-pie -O0 -s -m32 -o onefmt
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

size_t N = 0x100;
char secret[] = "whosyourdaddy\n";

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main() {
    char buf[N];
    init();
    memset(buf, '\0', N);
    system("echo Welcome to V-CTF!");
    puts("Here is Echo Godness.");
    printf("Please say something: ");
    fgets(buf, N, stdin);
    printf("Echo Godness says: ");
    printf(buf);
    if (0 == strcmp(buf, secret)) {
        puts("\nGreat! You've opened Zeus mode!");
    }
    return 0;
}
