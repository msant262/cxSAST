#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

// Buffer Overflow Vulnerabilities
void buffer_overflow_vuln(char* input) {
    char buffer[10];
    strcpy(buffer, input); // Unsafe strcpy
}

void strcat_vuln(char* input) {
    char buffer[20] = "Hello ";
    strcat(buffer, input); // Unsafe strcat
}

void gets_vuln() {
    char buffer[50];
    gets(buffer); // Dangerous gets function
}

// Command Injection Vulnerabilities
void command_injection_vuln(char* user_input) {
    char command[100];
    sprintf(command, "echo %s", user_input); // Unsafe command construction
    system(command);
}

void popen_vuln(char* user_input) {
    char command[100];
    sprintf(command, "ls %s", user_input);
    FILE* fp = popen(command, "r"); // Unsafe popen usage
    if (fp) {
        pclose(fp);
    }
}

// Format String Vulnerabilities
void format_string_vuln(char* user_input) {
    printf(user_input); // Unsafe printf with user input
}

void fprintf_vuln(char* user_input) {
    FILE* fp = fopen("output.txt", "w");
    if (fp) {
        fprintf(fp, user_input); // Unsafe fprintf
        fclose(fp);
    }
}

// Memory Management Vulnerabilities
void memory_leak_vuln() {
    char* buffer = (char*)malloc(100);
    // Forgot to free buffer
}

void use_after_free_vuln() {
    char* buffer = (char*)malloc(100);
    strcpy(buffer, "Hello");
    free(buffer);
    strcpy(buffer, "World"); // Use after free
}

// Hardcoded Secrets
void hardcoded_secrets() {
    const char* password = "SuperSecret123!";
    const char* api_key = "AKIAIOSFODNN7EXAMPLE";
    const char* token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
}

// SQL Injection (simulated)
void sql_injection_vuln(char* user_input) {
    char query[200];
    sprintf(query, "SELECT * FROM users WHERE username = '%s'", user_input);
    // Simulated database query
    printf("Executing query: %s\n", query);
}

// Path Traversal
void path_traversal_vuln(char* user_input) {
    char path[100];
    sprintf(path, "/var/www/uploads/%s", user_input);
    FILE* fp = fopen(path, "r");
    if (fp) {
        fclose(fp);
    }
}

int main() {
    char user_input[100];
    
    std::cout << "Enter input: ";
    std::cin >> user_input;
    
    // Demonstrate vulnerabilities
    buffer_overflow_vuln(user_input);
    command_injection_vuln(user_input);
    format_string_vuln(user_input);
    memory_leak_vuln();
    sql_injection_vuln(user_input);
    path_traversal_vuln(user_input);
    
    return 0;
} 