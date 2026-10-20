#include <string.h>

void test_cases(void) {
    char safe[16];
    strcpy(safe, "hello");

    char unsafe[4];
    strcpy(unsafe, "too long");
}
