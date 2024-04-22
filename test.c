#include <stdio.h>

void foo(void) {
    fprintf(stderr, "Hello World.\n");
}

int main(int argc, char *argv[]) { 
    int i;
    for(i=0;i<5;i++)
        foo();
    

    return 1;
}
