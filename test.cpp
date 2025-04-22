#include <iostream>
#include <cstring>
#include <cstdio>

void vulnerable_function(char* input) {
    char buffer[10];
    strcpy(buffer, input); // Buffer overflow
}

void insecure_command(char* user_input) {
    char command[100];
    sprintf(command, "echo %s", user_input); // Command injection
    system(command);
}

void format_string_vuln(char* user_input) {
    printf(user_input); // Format string vulnerability
}

int main() {
    char password[] = "secret123"; // Hardcoded secret
    char user_input[100];
    
    std::cout << "Enter input: ";
    std::cin >> user_input;
    
    vulnerable_function(user_input);
    insecure_command(user_input);
    format_string_vuln(user_input);
    
    return 0;
} 