#include <stdio.h>
#include <string.h>

/* Case 1: the analyzer can prove this literal fits char[16]. */
void safe_literal_copy(void) {
    char safe[16];
    strcpy(safe, "hello");
}

/* Case 2: source length is unknown; the analyzer must keep a finding. */
void copy_unknown_input(const char *input) {
    char buffer[16];
    strcpy(buffer, input);
}

/* Case 3: destination is a pointer, so capacity is not proven by this rule. */
void copy_to_pointer(void) {
    char storage[16];
    char *destination = storage;
    strcpy(destination, "hello");
}

/* Case 4: %s has no width limit and can overflow username. */
void read_username(void) {
    char username[16];
    scanf("%s", username);       /* should be reported */
    scanf("%15s", username);     /* width leaves room for NUL */
}

/* Case 5a: this formatted result fits in the destination. */
void format_into_large_buffer(void) {
    char message[16];
    sprintf(message, "user=%s", "admin");
}

/* Case 5b: formatted output exceeds the four-byte destination. */
void format_into_small_buffer(void) {
    char message[4];
    sprintf(message, "user=%s", "admin");
}
