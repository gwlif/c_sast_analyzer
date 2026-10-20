#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void safe_function() {
    printf("Это безопасно."); // Не должно сработать
}

int main() {
    char buffer[16];
    char* input = "Test string that is way too long for the buffer";

    // Уязвимость 1: strcpy
    strcpy(buffer, input);
    
    // Уязвимость 2: system
    system("ls -la");
    
    // Ложное срабатывание, которое мы подавляем маркером:
    strcpy(buffer, "Short string"); // ignore-sec

    return 0;
}