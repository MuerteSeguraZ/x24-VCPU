#include "vcpu.cpp"

int main() {
    try {
        CPU cpu(65536, 8192, 256);

        vector<string> prog = {
            "PRINT \"[BOOT] Testing Unary Operations\"",
            "",
            "# --- Test ABS (Absolute Value) ---",
            "PRINT \"\\n=== Testing ABS ===\"",
            "",
            "# ABS on positive number (should stay same)",
            "LOADI 42 r8_0",
            "PRINT \"Before ABS: r8_0=\"",
            "PRINT r8_0",
            "ABS r8_0",
            "PRINT \"After ABS: r8_0=\"",
            "PRINT r8_0",                    // Should still be 42
            "",
            "# ABS on negative number (8-bit)",
            "LOADI 200 r8_1",                // 200 = -56 in signed 8-bit
            "PRINT \"Before ABS: r8_1=\"",
            "PRINT r8_1",
            "ABS r8_1",
            "PRINT \"After ABS: r8_1=\"",
            "PRINT r8_1",                    // Should be 56
            "",
            "# ABS on -1",
            "LOADI 255 r8_2",                // 255 = -1 in signed 8-bit
            "PRINT \"Before ABS (255=-1): r8_2=\"",
            "PRINT r8_2",
            "ABS r8_2",
            "PRINT \"After ABS: r8_2=\"",
            "PRINT r8_2",                    // Should be 1
            "",
            "# ABS on 16-bit negative",
            "LOADI 65000 r16_0",             // Large value = negative in signed
            "PRINT \"Before ABS: r16_0=\"",
            "PRINT r16_0",
            "ABS r16_0",
            "PRINT \"After ABS: r16_0=\"",
            "PRINT r16_0",
            "",
            "# --- Test CLR (Clear to Zero) ---",
            "PRINT \"\\n=== Testing CLR ===\"",
            "",
            "# Clear 8-bit register",
            "LOADI 123 r8_3",
            "PRINT \"Before CLR: r8_3=\"",
            "PRINT r8_3",
            "CLR r8_3",
            "PRINT \"After CLR: r8_3=\"",
            "PRINT r8_3",                    // Should be 0
            "",
            "# Clear 16-bit register",
            "LOADI 54321 r16_1",
            "PRINT \"Before CLR: r16_1=\"",
            "PRINT r16_1",
            "CLR r16_1",
            "PRINT \"After CLR: r16_1=\"",
            "PRINT r16_1",                   // Should be 0
            "",
            "# --- Test SETZ/SETE (Set if Zero/Equal) ---",
            "PRINT \"\\n=== Testing SETZ/SETE ===\"",
            "",
            "# SETZ when ZF=1",
            "LCMP 5 5",                      // Compare equal -> ZF=1
            "SETZ r8_4",
            "PRINT \"SETZ (ZF=1): r8_4=\"",
            "PRINT r8_4",                    // Should be 1
            "",
            "# SETZ when ZF=0",
            "LCMP 5 10",                     // Compare not equal -> ZF=0
            "SETZ r8_5",
            "PRINT \"SETZ (ZF=0): r8_5=\"",
            "PRINT r8_5",                    // Should be 0
            "",
            "# --- Test SETNZ/SETNE (Set if Not Zero/Not Equal) ---",
            "PRINT \"\\n=== Testing SETNZ/SETNE ===\"",
            "",
            "# SETNZ when ZF=0",
            "LCMP 5 10",                     // Not equal -> ZF=0
            "SETNZ r8_6",
            "PRINT \"SETNZ (ZF=0): r8_6=\"",
            "PRINT r8_6",                    // Should be 1
            "",
            "# SETNZ when ZF=1",
            "LCMP 7 7",                      // Equal -> ZF=1
            "SETNZ r8_7",
            "PRINT \"SETNZ (ZF=1): r8_7=\"",
            "PRINT r8_7",                    // Should be 0
            "",
            "# --- Test SETC (Set if Carry) ---",
            "PRINT \"\\n=== Testing SETC ===\"",
            "",
            "# SETC when CF=1",
            "LOADI 200 r8_8",
            "LOADI 100 r8_9",
            "LUADD r8_9 r8_8",               // 200+100=300 (overflow) -> CF=1
            "SETC r8_10",
            "PRINT \"SETC (CF=1): r8_10=\"",
            "PRINT r8_10",                   // Should be 1
            "",
            "# SETC when CF=0",
            "CLC",                            // Clear carry
            "SETC r8_11",
            "PRINT \"SETC (CF=0): r8_11=\"",
            "PRINT r8_11",                   // Should be 0
            "",
            "# --- Test SETNC (Set if Not Carry) ---",
            "PRINT \"\\n=== Testing SETNC ===\"",
            "",
            "# SETNC when CF=0",
            "CLC",
            "SETNC r8_12",
            "PRINT \"SETNC (CF=0): r8_12=\"",
            "PRINT r8_12",                   // Should be 1
            "",
            "# SETNC when CF=1",
            "STC",
            "SETNC r8_13",
            "PRINT \"SETNC (CF=1): r8_13=\"",
            "PRINT r8_13",                   // Should be 0
            "",
            "# --- Test SETS (Set if Sign/Negative) ---",
            "PRINT \"\\n=== Testing SETS ===\"",
            "",
            "# SETS when SF=1 (negative result)",
            "LOADI 5 r8_14",
            "LOADI 10 r8_15",
            "LCMP r8_14 r8_15",              // 10-5=5 (positive) -> SF=0
            "SETS r8_16",
            "PRINT \"SETS (SF=0): r8_16=\"",
            "PRINT r8_16",                   // Should be 0
            "",
            "LOADI 10 r8_17",
            "LOADI 5 r8_18",
            "LCMP r8_17 r8_18",              // 5-10=-5 (negative) -> SF=1
            "SETS r8_19",
            "PRINT \"SETS (SF=1): r8_19=\"",
            "PRINT r8_19",                   // Should be 1
            "",
            "# --- Test SETNS (Set if Not Sign/Positive) ---",
            "PRINT \"\\n=== Testing SETNS ===\"",
            "",
            "# SETNS when SF=0",
            "LOADI 5 r8_20",
            "LOADI 10 r8_21",
            "LCMP r8_20 r8_21",              // 10-5=5 (positive) -> SF=0
            "SETNS r8_22",
            "PRINT \"SETNS (SF=0): r8_22=\"",
            "PRINT r8_22",                   // Should be 1
            "",
            "# --- Test SETL (Set if Less) ---",
            "PRINT \"\\n=== Testing SETL ===\"",
            "",
            "# SETL when less than",
            "LOADI 10 r8_23",
            "LOADI 5 r8_24",
            "LCMP r8_23 r8_24",              // 5-10=-5 (less) -> SF=1
            "SETL r8_25",
            "PRINT \"SETL (10>5): r8_25=\"",
            "PRINT r8_25",                   // Should be 1
            "",
            "# SETL when greater than",
            "LOADI 5 r8_26",
            "LOADI 10 r8_27",
            "LCMP r8_26 r8_27",              // 10-5=5 (greater) -> SF=0
            "SETL r8_28",
            "PRINT \"SETL (5<10): r8_28=\"",
            "PRINT r8_28",                   // Should be 0
            "",
            "# --- Test SETG (Set if Greater) ---",
            "PRINT \"\\n=== Testing SETG ===\"",
            "",
            "# SETG when greater than",
            "LOADI 5 r8_29",
            "LOADI 10 r8_30",
            "LCMP r8_29 r8_30",              // 10-5=5 (greater) -> SF=0, ZF=0
            "SETG r8_31",
            "PRINT \"SETG (5<10, so 10>5): r8_31=\"",
            "PRINT r8_31",                   // Should be 1
            "",
            "# SETG when equal (using 8-bit)",
            "LOADI 7 r8_0",
            "LOADI 7 r8_1",
            "LCMP r8_0 r8_1",                // Equal -> ZF=1
            "SETG r8_2",
            "PRINT \"SETG (7=7): r8_2=\"",
            "PRINT r8_2",                    // Should be 0
            "",
            "# --- Test SETLE (Set if Less or Equal) ---",
            "PRINT \"\\n=== Testing SETLE ===\"",
            "",
            "# SETLE when less",
            "LOADI 10 r16_5",
            "LOADI 5 r16_6",
            "HCMP r16_5 r16_6",              // Less -> SF=1
            "SETLE r16_7",
            "PRINT \"SETLE (less): r16_7=\"",
            "PRINT r16_7",                   // Should be 1
            "",
            "# SETLE when equal",
            "LOADI 9 r16_8",
            "LOADI 9 r16_9",
            "HCMP r16_8 r16_9",              // Equal -> ZF=1
            "SETLE r16_10",
            "PRINT \"SETLE (equal): r16_10=\"",
            "PRINT r16_10",                  // Should be 1
            "",
            "# SETLE when greater",
            "LOADI 5 r16_11",
            "LOADI 10 r16_12",
            "HCMP r16_11 r16_12",            // Greater -> SF=0, ZF=0
            "SETLE r16_13",
            "PRINT \"SETLE (greater): r16_13=\"",
            "PRINT r16_13",                  // Should be 0
            "",
            "# --- Test SETGE (Set if Greater or Equal) ---",
            "PRINT \"\\n=== Testing SETGE ===\"",
            "",
            "# SETGE when greater",
            "LOADI 5 r16_14",
            "LOADI 10 r16_15",
            "HCMP r16_14 r16_15",            // Greater -> SF=0
            "SETGE r16_16",
            "PRINT \"SETGE (greater): r16_16=\"",
            "PRINT r16_16",                  // Should be 1
            "",
            "# SETGE when equal",
            "LOADI 8 r16_17",
            "LOADI 8 r16_18",
            "HCMP r16_17 r16_18",            // Equal -> ZF=1, SF=0
            "SETGE r16_19",
            "PRINT \"SETGE (equal): r16_19=\"",
            "PRINT r16_19",                  // Should be 1
            "",
            "# SETGE when less",
            "LOADI 10 r16_20",
            "LOADI 5 r16_21",
            "HCMP r16_20 r16_21",            // Less -> SF=1
            "SETGE r16_22",
            "PRINT \"SETGE (less): r16_22=\"",
            "PRINT r16_22",                  // Should be 0
            "",
            "# --- Practical Example: Branchless Max ---",
            "PRINT \"\\n=== Branchless Max Example ===\"",
            "",
            "LOADI 42 r8_0",                 // Value A
            "LOADI 17 r8_1",                 // Value B
            "LCMP r8_0 r8_1",                // Compare A with B
            "SETG r8_2",                     // r8_2 = 1 if A > B, else 0
            "PRINT \"A=42, B=17\"",
            "PRINT \"A > B: \"",
            "PRINT r8_2",
            "",
            "# Another comparison",
            "LOADI 10 r8_3",
            "LOADI 99 r8_4",
            "LCMP r8_3 r8_4",
            "SETG r8_5",
            "PRINT \"A=10, B=99\"",
            "PRINT \"A > B: \"",
            "PRINT r8_5",
            "",
            "PRINT \"\\n[BOOT] All unary operation tests completed!\"",
            "QUIT"
        };

        cpu.load_program_lines(prog);
        cpu.run();

    } catch (const exception &ex) {
        cerr << "Runtime error: " << ex.what() << "\n";
        return 2;
    }
    return 0;
}