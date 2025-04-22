#include <iostream>
#include <cstring>
#include <string>
#include <mysql/mysql.h>
#include <sqlite3.h>
#include <pqxx/pqxx>

// Direct string concatenation vulnerability
void unsafe_direct_query(const char* user_input) {
    char query[1000];
    sprintf(query, "SELECT * FROM users WHERE username = '%s'", user_input);
    // Execute query (simulated)
    std::cout << "Executing query: " << query << std::endl;
}

// Multiple concatenations vulnerability
void unsafe_multiple_concat(const char* username, const char* password) {
    char query[1000];
    sprintf(query, "SELECT * FROM users WHERE username = '%s' AND password = '%s'", 
            username, password);
    // Execute query (simulated)
    std::cout << "Executing query: " << query << std::endl;
}

// Dynamic query construction vulnerability
void unsafe_dynamic_query(const char* table, const char* column, const char* value) {
    char query[1000];
    sprintf(query, "SELECT * FROM %s WHERE %s = '%s'", table, column, value);
    // Execute query (simulated)
    std::cout << "Executing query: " << query << std::endl;
}

// INSERT query vulnerability
void unsafe_insert(const char* username, const char* email) {
    char query[1000];
    sprintf(query, "INSERT INTO users (username, email) VALUES ('%s', '%s')", 
            username, email);
    // Execute query (simulated)
    std::cout << "Executing query: " << query << std::endl;
}

// UPDATE query vulnerability
void unsafe_update(const char* user_id, const char* new_status) {
    char query[1000];
    sprintf(query, "UPDATE users SET status = '%s' WHERE id = %s", 
            new_status, user_id);
    // Execute query (simulated)
    std::cout << "Executing query: " << query << std::endl;
}

// DELETE query vulnerability
void unsafe_delete(const char* condition) {
    char query[1000];
    sprintf(query, "DELETE FROM users WHERE %s", condition);
    // Execute query (simulated)
    std::cout << "Executing query: " << query << std::endl;
}

// LIKE clause vulnerability
void unsafe_like_search(const char* search_term) {
    char query[1000];
    sprintf(query, "SELECT * FROM products WHERE name LIKE '%%%s%%'", search_term);
    // Execute query (simulated)
    std::cout << "Executing query: " << query << std::endl;
}

// ORDER BY clause vulnerability
void unsafe_order_by(const char* column) {
    char query[1000];
    sprintf(query, "SELECT * FROM products ORDER BY %s", column);
    // Execute query (simulated)
    std::cout << "Executing query: " << query << std::endl;
}

// Multiple table vulnerability
void unsafe_join(const char* table1, const char* table2, const char* condition) {
    char query[1000];
    sprintf(query, "SELECT * FROM %s JOIN %s ON %s", table1, table2, condition);
    // Execute query (simulated)
    std::cout << "Executing query: " << query << std::endl;
}

// Stored procedure vulnerability
void unsafe_stored_proc(const char* proc_name, const char* params) {
    char query[1000];
    sprintf(query, "EXEC %s %s", proc_name, params);
    // Execute query (simulated)
    std::cout << "Executing query: " << query << std::endl;
}

int main() {
    // Test cases that could lead to SQL injection
    unsafe_direct_query("admin' OR '1'='1");
    unsafe_multiple_concat("admin", "' OR '1'='1");
    unsafe_dynamic_query("users", "role", "' OR '1'='1");
    unsafe_insert("admin', 'admin@evil.com'); DROP TABLE users; --", "fake@email.com");
    unsafe_update("1", "active'); DROP TABLE users; --");
    unsafe_delete("1=1; DROP TABLE users; --");
    unsafe_like_search("'); DROP TABLE products; --");
    unsafe_order_by("id; DROP TABLE products; --");
    unsafe_join("users", "roles", "1=1; DROP TABLE users; --");
    unsafe_stored_proc("update_user", "1; DROP TABLE users; --");
    
    return 0;
} 