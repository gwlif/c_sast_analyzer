#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void safe_function() {
    printf("System Status: OK\n");
}

void vulnerable_function() {
    char buffer[32];
    char user_input[128] = "Very long untrusted payload exceeding buffer size";

    // Issue 1: strcpy (Buffer Overflow)
    strcpy(buffer, user_input);

    // Issue 2: system call (Command Injection)
    system("ls -la /tmp");

    // Suppressed issue (False Positive suppression test)
    strcpy(buffer, "Safe Literal"); // ignore-sec
}

int main() {
    safe_function();
    vulnerable_function();
    return 0;
}
