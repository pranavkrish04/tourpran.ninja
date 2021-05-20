#include <stdio.h>
#include <stdlib.h>

// gcc ret2win_pie.c -o ret2win_pie -fno-stack-protector

__attribute__((constructor)) void ignore_me() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void win(long arg1) {
    char* cmd = "/bin/sh";
    if (arg1 == 0xdeadbeefcafebabe) {
        puts("Congrats!!!");
        execve(cmd, NULL, NULL);
    } else {
        puts("Forgot ROP. That's sad :<");
    }
}

int main(int argc, char** argv, char** environ) {
    char shot[0x60];

    puts("Aim and hit the bull's eye");
    fgets(shot, sizeof(shot), stdin);
    printf(shot);

    puts("Sad you missed it. Try one more time");
    gets(shot);
}
