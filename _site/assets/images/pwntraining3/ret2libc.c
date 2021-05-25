#include <stdio.h>

// gcc ret2libc.c -o ret2libc -fno-stack-protector -no-pie

__attribute__((constructor)) void ignore_me(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main(int argc, char** argv, char** environ){
    char buf[0x60];

    puts("Let's take the game to another level");
    puts("Are you in?");

    gets(buf);
}