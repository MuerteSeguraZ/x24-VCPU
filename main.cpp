#include <iostream>
#include <vector>
#include <string>
#include "vcpu.cpp"

using namespace std;

int main() {
    try {
        CPU cpu;
        
        vector<string> test_program = {
    "# Priority Interrupt Preemption Test",
    "",
    "# Setup handlers",
    "SETVEC 0 low_pri_handler",
    "SETVEC 1 mid_pri_handler", 
    "SETVEC 2 high_pri_handler",
    "SETVEC 3 nmi_handler",
    "",
    "# Set priorities",
    "SETPRI 0 5   # Low priority",
    "SETPRI 1 10  # Medium priority",
    "SETPRI 2 15  # High priority",
    "SETPRI 3 20  # NMI (non-maskable)",
    "",
    "PRINT \"Test 1: Triggering all interrupts with CLI (disabled)\"",
    "CLI",
    "TRIGGER 0",
    "TRIGGER 1",
    "TRIGGER 2",
    "TRIGGER 3",
    "PRINT \"All interrupts queued. Enabling with STI...\"",
    "STI",
    "NOP",
    "NOP",
    "NOP",
    "PRINT \"Test 1 complete\"",
    "PRINT \"\"",
    "",
    "PRINT \"Test 2: High priority preempting low priority handler\"",
    "CLI",
    "TRIGGER 0  # Low priority - will run first",
    "STI",
    "NOP",
    "NOP",
    "NOP",
    "PRINT \"Test 2 complete\"",
    "PRINT \"\"",
    "",
    "QUIT",
    "",
    "low_pri_handler:",
    "    PRINT \"  [Low priority START]\"",
    "    STI  # Re-enable interrupts so we can be preempted",
    "    # Simulate long work - trigger high priority during this",
    "    HPUT 0 r16_1",
    "    HPUT 0 r16_3  # Flag: have we triggered interrupt yet?",
    "    HPUT 50 r16_0",
   "loop_low:",
"    HUADD 1 r16_1",
"    # Debug: print counter every 10 iterations",
"    HPUT 10 r16_4",
"    HCMP r16_4 r16_1",
"    JNE skip_debug",
"    PRINT r16_0",
"skip_debug:",
"    # Only trigger ONCE when we hit 25",
"    HCMP 25 r16_1",
"    JNE skip_trigger",
"    HCMP 0 r16_3",
"    JNE skip_trigger",
"    PRINT \"  [Low: triggering high priority interrupt!]\"",
"    HPUT 1 r16_3",
"    TRIGGER 2",
"skip_trigger:",
"    DEC r16_0",
"    HCMP 0 r16_0",
"    JG loop_low",
"    PRINT \"  [Low priority END]\"",
"    IRET",
    "mid_pri_handler:",
    "    PRINT \"  [Medium priority handler]\"",
    "    IRET",
    "",
    "high_pri_handler:",
    "    PRINT \"  [High priority PREEMPTED low priority!]\"",
    "    IRET",
    "",
    "nmi_handler:",
    "    PRINT \"  [NMI handler - CRITICAL!]\"",
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