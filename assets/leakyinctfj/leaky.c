#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>
#include<unistd.h>

int bal = 100;
void use_tape(){
char experience[50];
char flag[50];

FILE *fp;
fp = fopen("flag.txt", "rb");
if(fp != NULL){
fgets(flag, 50, fp);
fclose(fp);

printf("Please give us your feedback!\n");
fgets(experience, 50, stdin);
printf(experience);
exit(0);
}else{
printf("Error opening file!\n");
exit(1);
}

}

void check_leaks(){
char leak[100];

printf("You currently have %d dollars with you!\n", bal);

printf("Where would you like to check your leaks? \n");
fgets(leak, 100, stdin);
printf(leak);

}

void call_plumber(){
printf("Why must you call the plumber when you can fix the leak yourself?\n");
}

void buy_repair_kit(){
if(bal == 200){
use_tape();
}else{
printf("You do not have enough balance! :(\n");
}
}

void initialize()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	alarm(30);
}

int main(){
char choice; int bal;

initialize();

printf("Welcome to my home!\nI have recently bought a new house, however, there seems to be a small leakage problem with the pipes.\nI was hoping you could help me fix it.\n");
while(1){
printf("\n1. Check for leaks\n2. Call plumber\n3. Buy repair kit\n\nChoice: ");

scanf("%c", &choice);
getchar();
fflush(stdin);

switch(choice){
	case '1':
		check_leaks();
		break;
	case '2':
		call_plumber();
		break;
	case '3':
		buy_repair_kit();
		break;
	default:
		printf("Invalid choice: \n");
		break;
}
}
return 0;

}
