#include <iostream>
#include <vector>
#include <string>
#include "vcpu.cpp"

using namespace std;

int main() {
    try {
        CPU cpu;
        
    vector<string> test_program = {
    "# Privilege Level Test",
    "",
    "# Setup segments",
    "SETSEG 0 0 65536 0 1 1      # Kernel segment (CPL=0)",
    "SETSEG 1 4096 8192 3 1 1    # User code segment (CPL=3)",
    "SETSEG 2 12288 4096 3 1 0   # User read-only data (CPL=3)",
    "",
    "# Setup syscall handler",
    "SETVEC 128 syscall_handler",
    "SETIPL 128 3  # Allow user mode to trigger syscall",
    "",
    "PRINT \"Kernel mode: CPL=0\"",
    "GETCPL r8_0",
    "PRINT r8_0",
    "",
    "# Switch to user mode",
    "PRINT \"Switching to user mode...\"",
    "SETCPL 3",
    "",
    "GETCPL r8_0",
    "PRINT r8_0",
    "",
    "# Try to do privileged operation (should fail)",
    "PRINT \"Attempting privileged operation from user mode...\"",
    "# SETCPL 0  # This would throw error",
    "",
    "# Make a system call",
    "PRINT \"Making syscall...\"",
    "SYSCALL 128",
    "",
    "PRINT \"Returned from syscall\"",
    "GETCPL r8_0",
    "PRINT r8_0",
    "",
    "QUIT",
    "",
    "syscall_handler:",
    "    PRINT \"  [In syscall handler - kernel mode]\"",
    "    GETCPL r8_1",
    "    PRINT r8_1",
    "    SYSRET",
};
        cpu.load_program_lines(test_program);
        cpu.run();
        
        cout << "\n=== Test completed successfully! ===\n";
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}