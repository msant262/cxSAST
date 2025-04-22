#include <iostream>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Buffer Overflow Vulnerability - No size check
void buffer_overflow_vulnerable(char* input) {
    char buffer[10];
    strcpy(buffer, input);  // Buffer overflow vulnerability
    printf("Buffer content: %s\n", buffer);
}

// Command Injection Vulnerability - No input validation
void command_injection_vulnerable(char* userInput) {
    char command[100];
    sprintf(command, "ls %s", userInput);  // Command injection vulnerability
    system(command);
}

// Memory Leak - No free
void memory_leak_vulnerable() {
    char* ptr = (char*)malloc(100);  // Memory leak - no free
    strcpy(ptr, "Hello World");
    printf("Memory content: %s\n", ptr);
    // Missing free(ptr)
}

// Use After Free
void use_after_free_vulnerable() {
    char* ptr = (char*)malloc(100);
    strcpy(ptr, "Hello World");
    free(ptr);
    printf("Memory content: %s\n", ptr);  // Use after free vulnerability
}

int main() {
    // Test buffer overflow
    char* longInput = "This is a very long input that will cause a buffer overflow";
    buffer_overflow_vulnerable(longInput);
    
    // Test command injection
    char* userInput = "; rm -rf /";  // Dangerous command
    command_injection_vulnerable(userInput);
    
    // Test memory leak
    memory_leak_vulnerable();
    
    // Test use after free
    use_after_free_vulnerable();
    
    return 0;
} 