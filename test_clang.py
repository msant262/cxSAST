import clang.cindex
import os

# Configure libclang
libclang_path = '/opt/homebrew/Cellar/llvm/20.1.3/lib/libclang.dylib'
print(f"libclang path: {libclang_path}")
print(f"libclang exists: {os.path.exists(libclang_path)}")
print(f"libclang readable: {os.access(libclang_path, os.R_OK)}")

# Set the library file
clang.cindex.Config.set_library_file(libclang_path)

# Create index
print("Creating index...")
index = clang.cindex.Index.create()
print("Index created successfully")

# Parse test file
test_file = "test.cpp"
print(f"Parsing file: {test_file}")
tu = index.parse(test_file)
print(f"Translation unit: {tu.spelling}")

# Visit nodes
def visit_node(node):
    print(f"Node: {node.kind} at line {node.location.line}")
    for child in node.get_children():
        visit_node(child)

print("Visiting nodes...")
visit_node(tu.cursor)
print("Done") 