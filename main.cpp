#include <iostream>
#include <vector>
#include <string>
#include "vcpu.cpp"

using namespace std;

int main() {
    try {
        CPU cpu;
        
        vector<string> test_program = {
    "# Asynchronous Hardware Interrupt Test",
    "",
    "# Setup handlers",
    "HPUT 100 r16_0",
    "SETVEC 0 timer_handler",
    "HPUT 200 r16_0", 
    "SETVEC 1 io_handler",
    "",
    "# Initialize counters",
    "LPUT 0 r8_0  # Timer interrupt count",
    "LPUT 0 r8_1  # I/O interrupt count",
    "HPUT 0 r16_2 # Instruction counter",
    "",
    "# Start timer - fires every 10 instructions on interrupt 0",
    "SETTIMER 30 0",
    "",
    "# Schedule some I/O operations",
    "SCHEDIO 25 1   # I/O completes after 25 cycles",
    "SCHEDIO 50 1   # Another I/O after 50 cycles",
    "SCHEDIO 75 1   # Another I/O after 75 cycles",
    "",
    "PRINT \"Starting main loop...\"",
    "",
    "# Main program loop - just counts",
    "main_loop:",
    "    HUADD 1 r16_2",
    "    HCMP 200 r16_2",
    "    JL main_loop",
    "",
    "STOPTIMER",
    "",
    "PRINT \"\\nMain loop complete!\"",
    "PRINT \"Instructions executed:\"",
    "PRINT r16_2",
    "PRINT \"Timer interrupts:\"",
    "PRINT r8_0",
    "PRINT \"I/O interrupts:\"", 
    "PRINT r8_1",
    "",
    "QUIT",
    "",
    "timer_handler:",
    "    PRINT \"  [TICK]\"",
    "    LPUT 1 r8_10",
    "    LUADD r8_10 r8_0",
    "    IRET",
    "",
    "io_handler:",
    "    PRINT \"  [I/O Complete]\"",
    "    LPUT 1 r8_10",
    "    LUADD r8_10 r8_1",
    "    IRET"
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