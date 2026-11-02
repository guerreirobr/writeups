#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv) {
    int offset = 0;

    // Se o script Python passar um offset, usamos esse valor
    // para testar segundos próximos ao time(0) do servidor.
    if (argc > 1) {
        offset = atoi(argv[1]);
    }

    // O binário the_office faz srand(time(0)) e depois rand().
    // Aqui reproduzimos o mesmo cálculo.
    srand(time(0) + offset);

    printf("%d\n", rand());

    return 0;
}
