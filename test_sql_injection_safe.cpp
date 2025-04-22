#include <iostream>
#include <cstring>
#include <string>
#include <mysql/mysql.h>
#include <sqlite3.h>
#include <pqxx/pqxx>

// Safe implementation using prepared statements
void safe_direct_query(MYSQL* conn, const char* user_input) {
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    const char* query = "SELECT * FROM users WHERE username = ?";
    mysql_stmt_prepare(stmt, query, strlen(query));
    
    // Bind parameters
    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (void*)user_input;
    bind[0].buffer_length = strlen(user_input);
    mysql_stmt_bind_param(stmt, bind);
    
    // Execute and clean up
    mysql_stmt_execute(stmt);
    mysql_stmt_close(stmt);
}

// Safe implementation with multiple parameters
void safe_multiple_params(MYSQL* conn, const char* username, const char* password) {
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    const char* query = "SELECT * FROM users WHERE username = ? AND password = ?";
    mysql_stmt_prepare(stmt, query, strlen(query));
    
    // Bind parameters
    MYSQL_BIND bind[2];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (void*)username;
    bind[0].buffer_length = strlen(username);
    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (void*)password;
    bind[1].buffer_length = strlen(password);
    mysql_stmt_bind_param(stmt, bind);
    
    // Execute and clean up
    mysql_stmt_execute(stmt);
    mysql_stmt_close(stmt);
}

// Safe implementation for INSERT
void safe_insert(MYSQL* conn, const char* username, const char* email) {
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    const char* query = "INSERT INTO users (username, email) VALUES (?, ?)";
    mysql_stmt_prepare(stmt, query, strlen(query));
    
    // Bind parameters
    MYSQL_BIND bind[2];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (void*)username;
    bind[0].buffer_length = strlen(username);
    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (void*)email;
    bind[1].buffer_length = strlen(email);
    mysql_stmt_bind_param(stmt, bind);
    
    // Execute and clean up
    mysql_stmt_execute(stmt);
    mysql_stmt_close(stmt);
}

// Safe implementation for UPDATE
void safe_update(MYSQL* conn, const char* user_id, const char* new_status) {
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    const char* query = "UPDATE users SET status = ? WHERE id = ?";
    mysql_stmt_prepare(stmt, query, strlen(query));
    
    // Bind parameters
    MYSQL_BIND bind[2];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (void*)new_status;
    bind[0].buffer_length = strlen(new_status);
    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (void*)user_id;
    bind[1].buffer_length = strlen(user_id);
    mysql_stmt_bind_param(stmt, bind);
    
    // Execute and clean up
    mysql_stmt_execute(stmt);
    mysql_stmt_close(stmt);
}

// Safe implementation for LIKE search
void safe_like_search(MYSQL* conn, const char* search_term) {
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    const char* query = "SELECT * FROM products WHERE name LIKE CONCAT('%', ?, '%')";
    mysql_stmt_prepare(stmt, query, strlen(query));
    
    // Bind parameters
    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (void*)search_term;
    bind[0].buffer_length = strlen(search_term);
    mysql_stmt_bind_param(stmt, bind);
    
    // Execute and clean up
    mysql_stmt_execute(stmt);
    mysql_stmt_close(stmt);
}

// Safe implementation for ORDER BY
void safe_order_by(MYSQL* conn, const char* column) {
    // Validate column name against whitelist
    const char* valid_columns[] = {"id", "name", "price", "created_at"};
    bool is_valid = false;
    for (const char* valid : valid_columns) {
        if (strcmp(column, valid) == 0) {
            is_valid = true;
            break;
        }
    }
    
    if (!is_valid) {
        std::cerr << "Invalid column name" << std::endl;
        return;
    }
    
    // Use prepared statement with validated column name
    std::string query = "SELECT * FROM products ORDER BY " + std::string(column);
    mysql_query(conn, query.c_str());
}

// Safe implementation for stored procedure
void safe_stored_proc(MYSQL* conn, const char* proc_name, const char* param) {
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    const char* query = "CALL sp_update_user(?)";
    mysql_stmt_prepare(stmt, query, strlen(query));
    
    // Bind parameters
    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (void*)param;
    bind[0].buffer_length = strlen(param);
    mysql_stmt_bind_param(stmt, bind);
    
    // Execute and clean up
    mysql_stmt_execute(stmt);
    mysql_stmt_close(stmt);
}

int main() {
    // Example usage (connection handling omitted for brevity)
    MYSQL* conn = mysql_init(NULL);
    
    // Test cases with safe implementations
    safe_direct_query(conn, "admin");
    safe_multiple_params(conn, "admin", "password123");
    safe_insert(conn, "newuser", "user@example.com");
    safe_update(conn, "1", "active");
    safe_like_search(conn, "product");
    safe_order_by(conn, "created_at");
    safe_stored_proc(conn, "update_user", "1");
    
    mysql_close(conn);
    return 0;
} 