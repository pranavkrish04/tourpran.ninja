#include <stdio.h>

// gcc ret2libc_canary.c -o ret2libc_canary -fstack-protector

__attribute__((constructor)) void ignore_me(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main(int argc, char** argv, char** environ){
    char shot[0x60];

    puts("So you wanna try again. Go ahead :)");
    fgets(shot, sizeof(shot), stdin);
    printf(shot);

    puts("Missed again??? I'm so disappointed.");
    printf("Clarification: ");
    gets(shot);
}
