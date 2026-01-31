#include <iostream>
#include <vector>
#include <string>
#include "vcpu.cpp"  // Replace with your actual header file name

using namespace std;

int main() {
    try {
        CPU cpu;
        
        vector<string> test_program = {
    "# CPUID Test Program",
    "",
    "# Test 1: Function 0 - Vendor ID",
    "PRINT \"Test 1: CPUID Function 0 - Vendor ID\"",
    "CPUID 0",
    "PRINT \"Max function supported (r16_0):\"",
    "PRINT r16_0",
    "PRINT \"Vendor ID parts:\"",
    "PRINT \"r16_1 (should contain 'Vi'):\"",
    "PRINT r16_1",
    "PRINT \"r16_3 (should contain 'ua'):\"",
    "PRINT r16_3",
    "PRINT \"r16_2 (should contain 'PU'):\"",
    "PRINT r16_2",
    "",
    "# Test 2: Function 1 - Processor Info",
    "PRINT \"\\nTest 2: CPUID Function 1 - Processor Info\"",
    "CPUID 1",
    "PRINT \"Version info (r16_0):\"",
    "PRINT r16_0",
    "PRINT \"Brand/CLFLUSH (r16_1):\"",
    "PRINT r16_1",
    "PRINT \"Extended features (r16_2):\"",
    "PRINT r16_2",
    "PRINT \"Standard features (r16_3):\"",
    "PRINT r16_3",
    "",
    "# Test 3: Check for FPU support (bit 0 of EDX from function 1)",
    "PRINT \"\\nTest 3: Checking FPU support\"",
    "CPUID 1",
    "MOV r16_3 r16_4",    // Copy EDX
    "HAND 1 r16_4",       // Check bit 0 (use HAND for 16-bit)
    "HCMP 1 r16_4",
    "JZ has_fpu",
    "PRINT \"No FPU support (FAILED)\"",
    "JMP test4",
    "has_fpu:",
    "PRINT \"FPU supported (PASSED)\"",
    "",
    "test4:",
    "# Test 4: Check for CMOV support (bit 15 of EDX from function 1)",
    "PRINT \"\\nTest 4: Checking CMOV support\"",
    "CPUID 1",
    "MOV r16_3 r16_5",    // Copy EDX
    "HSHR 15 r16_5",      // Shift bit 15 to bit 0 (use HSHR for 16-bit)
    "HAND 1 r16_5",       // Use HAND for 16-bit
    "HCMP 1 r16_5",
    "JZ has_cmov",
    "PRINT \"No CMOV support (FAILED)\"",
    "JMP test5",
    "has_cmov:",
    "PRINT \"CMOV supported (PASSED)\"",
    "",
    "test5:",
    "# Test 5: Function 2 - Cache Info",
    "PRINT \"\\nTest 5: CPUID Function 2 - Cache Info\"",
    "CPUID 2",
    "PRINT \"Cache descriptor (r16_0):\"",
    "PRINT r16_0",
    "PRINT \"L1 data cache (r16_1):\"",
    "PRINT r16_1",
    "PRINT \"L1 instruction cache (r16_2):\"",
    "PRINT r16_2",
    "",
    "# Test 6: Extended function support",
    "PRINT \"\\nTest 6: CPUID Function 0x80000000 - Extended Support\"",
    "CPUID 0x8000",
    "PRINT \"Max extended function (r16_0, should be 0x8004 = 32772):\"",
    "PRINT r16_0",
    "",
    "# Test 7: Processor brand string part 1",
    "PRINT \"\\nTest 7: CPUID Function 0x80000002 - Brand String Part 1\"",
    "CPUID 0x8002",
    "PRINT \"Brand string part 1 (r16_0 should contain 'Vi'):\"",
    "PRINT r16_0",
    "PRINT \"r16_1 (should contain 'rt'):\"",
    "PRINT r16_1",
    "",
    "# Test 8: Processor brand string part 2",
    "PRINT \"\\nTest 8: CPUID Function 0x80000003 - Brand String Part 2\"",
    "CPUID 0x8003",
    "PRINT \"Brand string part 2 (r16_0 should contain 'CP'):\"",
    "PRINT r16_0",
    "",
    "# Test 9: Processor brand string part 3",
    "PRINT \"\\nTest 9: CPUID Function 0x80000004 - Brand String Part 3\"",
    "CPUID 0x8004",
    "PRINT \"Brand string part 3 (r16_0 should contain ' b'):\"",
    "PRINT r16_0",
    "",
    "# Test 10: Unknown function",
    "PRINT \"\\nTest 10: CPUID Unknown Function\"",
    "CPUID 99",
    "PRINT \"Unknown function should return zeros:\"",
    "PRINT \"r16_0:\"",
    "PRINT r16_0",
    "PRINT \"r16_1:\"",
    "PRINT r16_1",
    "",
    "# Test 11: Using register as function parameter",
    "PRINT \"\\nTest 11: CPUID with register parameter\"",
    "MOV 1 r8_0",
    "CPUID r8_0",
    "PRINT \"Called CPUID(1) via r8_0\"",
    "PRINT \"Version (r16_0):\"",
    "PRINT r16_0",
    "",
    "# Test 12: Family/Model extraction",
    "PRINT \"\\nTest 12: Extracting CPU Family and Model\"",
    "CPUID 1",
    "MOV r16_0 r16_6",    // Copy version info
    "HSHR 8 r16_6",       // Shift to get family (use HSHR for 16-bit)
    "HAND 0x0F r16_6",    // Mask to get family (use HAND for 16-bit)
    "PRINT \"CPU Family (should be 6):\"",
    "PRINT r16_6",
    "",
    "CPUID 1",
    "MOV r16_0 r16_7",    // Copy version info again
    "HSHR 4 r16_7",       // Shift to get model (use HSHR for 16-bit)
    "HAND 0x0F r16_7",    // Mask to get model (use HAND for 16-bit)
    "PRINT \"CPU Model (should be 1):\"",
    "PRINT r16_7",
    "",
    "PRINT \"\\nAll CPUID tests completed!\"",
    "PRINT \"\\nCPU Identity: VirtualCPU v1.0 Muerte\"",
    "PRINT \"Supported features: FPU, CMOV, String Ops, Bit Manipulation, Atomics\"",
    "EXIT"
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