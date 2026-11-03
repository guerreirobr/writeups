#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    signal(SIGALRM, SIG_DFL);
    alarm(120);
}

void banner(void) {
    puts("================================================");
    puts("   Fluid Banking Terminal  v3.1.4");
    puts("   \"Your finances, secured.\"");
    puts("================================================");
    puts("");
}

void menu(void) {
    puts("  [1] Check Balance");
    puts("  [2] Transfer Funds");
    puts("  [3] Exit");
    printf("\n> ");
}

void check_balance(void) {
    char note[128];

    printf("\nEnter account memo: ");
    memset(note, 0, sizeof(note));
    int n = read(0, note, 127);
    if (n > 0 && note[n - 1] == '\n')
        note[n - 1] = '\0';

    printf("\n--- Account Statement ---\n");
    printf("Account Holder: ");
    printf(note);
    printf("\nBalance: $13,370.00\n");
    printf("Status: Active\n");
    printf("-------------------------\n\n");
}

void transfer_funds(void) {
    char amount[64];

    printf("\nEnter transfer details: ");
    memset(amount, 0, sizeof(amount));
    read(0, amount, 256);

    printf("Processing transfer...\n");
    printf("Transfer complete.\n\n");
}

int main(void) {
    setup();
    banner();

    char choice[8];

    while (1) {
        menu();
        memset(choice, 0, sizeof(choice));
        int n = read(0, choice, 7);
        if (n <= 0)
            break;

        switch (choice[0]) {
        case '1':
            check_balance();
            break;
        case '2':
            transfer_funds();
            break;
        case '3':
            printf("Goodbye.\n");
            return 0;
        default:
            printf("Invalid option.\n\n");
            break;
        }
    }

    return 0;
}
