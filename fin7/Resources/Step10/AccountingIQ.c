#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]){
    while (1){ 
        const char *creditCard = "Network:Visa, CardNumber:4485952502593344, Name:John Doe, Address:593 Oak Hill Road, Country: United States of America, CVV:367, Exp:3/28";
        printf("Record = %s\nAddress = %d\n", creditCard, creditCard);
        printf("press any key to continue\n");
        char input;
        scanf("%c", &input);
    }
}