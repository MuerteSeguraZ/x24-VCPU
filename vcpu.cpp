#include <bits/stdc++.h>
#include "vcfs.c"
using namespace std;

unordered_map<string, size_t> labels;

using u8  = uint8_t;
using u16 = uint16_t;
using i8  = int8_t;
using i16 = int16_t;
using u32 = uint32_t;
using i32 = int32_t;  // ADD THIS
using u64 = uint64_t;  // ADD THIS

static string trim(const string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static vector<string> split_tok(const string &line) {
    vector<string> t;
    string cur;
    bool inbr = false;
    bool inquote = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];

        if (c == '"') {
            inquote = !inquote;
            cur.push_back(c);
            continue;
        }

        if (!inquote) {
            if (c == '[') inbr = true;
            if (c == ']') inbr = false;
        }

        if (!inbr && !inquote && isspace((unsigned char)c)) {
            if (!cur.empty()) {
                t.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }

    if (!cur.empty())
        t.push_back(cur);

    return t;
}

struct CPU {
    // registers
    array<u8, 32> regs8{};
    array<u16, 32> regs16{};
    array<float, 32> regs_f32{};
    array<double, 32> regs_f64{};
    array<u32, 256> interrupt_vector_table{};
    queue<u8> pending_interrupts;
    u32 SP = 0; 
    u32 timer_counter = 0;
    u32 timer_interval = 0;
    int interrupt_depth = 0;
    
    // memory
    vector<u8> mem;
    size_t mem_size = 65536;
    size_t stack_base = 0;
    size_t stack_size = 1024;

    // flags
    bool ZF = false;  // Zero Flag
    bool SF = false;  // Sign Flag
    bool CF = false;  // Carry Flag
    bool OF = false;  // Overflow Flag
    bool FZ = false;
    bool FN = false;
    bool FE = false;
    bool FG = false;
    bool FL = false;
    bool interrupt_enabled = true;
    bool trap_flag = false;
    bool timer_enabled = false;
    bool in_interrupt_handler = false;

    // memory layout
    size_t program_region = 0;
    size_t program_size = 0;
    size_t ram16_offset = 0;
    size_t ram16_size = 0;
    size_t ram8_offset = 0;
    size_t ram8_size = 256;

    // program
    vector<string> program;

    struct PendingIO {
        u8 interrupt_num;
        u32 cycles_remaining;
    };
    vector<PendingIO> pending_io;

    void set_flags(int a, int b) {
        int res = b - a;
        ZF = (res == 0);
        SF = (res < 0);
        // Carry flag: set if unsigned borrow occurs
        CF = ((unsigned)b < (unsigned)a);
        // Overflow flag: set if signed overflow occurs
        // Overflow if signs of b and -a are same, but result has different sign
        OF = (((b ^ (-a)) & 0x80000000) == 0) && (((b ^ res) & 0x80000000) != 0);
    }

    void set_flags_add(int a, int b, int result, bool is_16bit) {
        if (is_16bit) {
            ZF = ((result & 0xFFFF) == 0);
            SF = ((result & 0x8000) != 0);
            CF = (result > 0xFFFF);
            // Overflow: signs of operands same, but result different
            OF = (((a & 0x8000) == (b & 0x8000)) && ((result & 0x8000) != (a & 0x8000)));
        } else {
            ZF = ((result & 0xFF) == 0);
            SF = ((result & 0x80) != 0);
            CF = (result > 0xFF);
            OF = (((a & 0x80) == (b & 0x80)) && ((result & 0x80) != (a & 0x80)));
        }
    }

    void set_flags_sub(int a, int b, int result, bool is_16bit) {
        if (is_16bit) {
            ZF = ((result & 0xFFFF) == 0);
            SF = ((result & 0x8000) != 0);
            CF = ((unsigned)b < (unsigned)a);
            OF = (((b & 0x8000) != (a & 0x8000)) && ((result & 0x8000) != (b & 0x8000)));
        } else {
            ZF = ((result & 0xFF) == 0);
            SF = ((result & 0x80) != 0);
            CF = ((unsigned)(b & 0xFF) < (unsigned)(a & 0xFF));
            OF = (((b & 0x80) != (a & 0x80)) && ((result & 0x80) != (b & 0x80)));
        }
    }

    void preprocess_labels() {
        labels.clear();
        for (size_t i = 0; i < program.size(); ++i) {
            string line = trim(program[i]);
            if (!line.empty() && line.back() == ':') {
                string label = line.substr(0, line.size() - 1);
                labels[label] = i;
            }
        }
    }

    void register_interrupt_handler(u8 interrupt_num, u32 handler_address) {
        interrupt_vector_table[interrupt_num] = handler_address;
    }

    void trigger_interrupt(u8 interrupt_num) {
    pending_interrupts.push(interrupt_num);
}

    void handle_interrupt(u8 interrupt_num, size_t& pc) {
        if (!interrupt_enabled && interrupt_num < 32) {
            // Non-maskable interrupts (0-31) can't be disabled
            // For simplicity, we'll make interrupts 0-31 non-maskable
        } else if (!interrupt_enabled) {
            return;  // Interrupts disabled
        }
    
        // Get handler address from IVT
        u32 handler_addr = interrupt_vector_table[interrupt_num];
    
        if (handler_addr == 0) {
            cout << "WARNING: No handler for interrupt " << (int)interrupt_num << "\n";
            return;
        }   
    
        // Push flags (simplified - just store key flags)
        u16 flags = 0;
        flags |= (ZF ? (1 << 0) : 0);
        flags |= (SF ? (1 << 1) : 0);
        flags |= (CF ? (1 << 2) : 0);
        flags |= (OF ? (1 << 3) : 0);
        flags |= (interrupt_enabled ? (1 << 4) : 0);
        flags |= (trap_flag ? (1 << 5) : 0);
        
        if (SP < stack_base + 4) throw runtime_error("stack overflow during interrupt");
        
        // Push return address and flags (like x86)
        SP -= 2;
        mem_write16_at(SP, (u16)pc);  // Return address
        SP -= 2;
        mem_write16_at(SP, flags);    // Flags
        
        // Disable interrupts during handler (can be re-enabled with STI)
        interrupt_enabled = false;
        in_interrupt_handler = true;
        interrupt_depth++;
        
        // Jump to handler
        if (handler_addr >= program.size()) {
            throw runtime_error("interrupt handler address out of bounds");
        }
        pc = handler_addr;
    }   

    CPU(size_t full_mem = 65536, size_t ram16_sz = 4096, size_t ram8_sz = 256) {
        if (full_mem < ram8_sz + 1) throw runtime_error("memory too small");
        mem_size = full_mem;
        mem.assign(mem_size, 0);

        // 8-bit RAM at top
        ram8_size = min<size_t>(ram8_sz, 256);
        ram8_offset = mem_size - ram8_size;

        // stack below 8-bit RAM
        stack_size = 1024;
        if (stack_size > ram8_offset)
            stack_size = ram8_offset;

        stack_base = ram8_offset - stack_size;
        SP = stack_base + stack_size;

        // program & 16-bit RAM
        program_region = 0;
        program_size = 0;
        ram16_offset = 0;
        ram16_size = ram16_sz;
    }

    void load_program_lines(const vector<string>& lines) {
        program = lines;
        program_size = lines.size();
        size_t reserve = 0; 
        ram16_offset = 0 + reserve;
        if (ram8_size > 256) ram8_size = 256;
        ram8_offset = mem_size - ram8_size;
        if (ram16_offset >= ram8_offset) throw runtime_error("not enough memory for configured regions");
        ram16_size = min(ram16_size, ram8_offset - ram16_offset);
    }

    bool is_r8(const string &s) {
        if (s.size() < 3) return false;
        if (s.rfind("r8", 0) == 0) {
            string num;
            if (s.size() > 2 && s[2] == '_') num = s.substr(3);
            else num = s.substr(2);
            if (num.empty()) return false;
            try { 
                int n = stoi(num); 
                return n >= 0 && n < 32; 
            } catch(...) {}
        }
        return false;
    }

    bool is_r16(const string &s) {
        if (s.size() < 4) return false;
        if (s.rfind("r16", 0) == 0) {
            string num;
            if (s.size() > 3 && s[3] == '_') num = s.substr(4);
            else num = s.substr(3);
            if (num.empty()) return false;
            try { 
                int n = stoi(num); 
                return n >= 0 && n < 32; 
            } catch(...) {}
        }
        return false;
    }

    bool is_f32(const string &s) {
        if (s.size() < 4) return false;
        if (s.rfind("f32", 0) == 0) {
            string num;
            if (s.size() > 3 && s[3] == '_') num = s.substr(4);
            else num = s.substr(3);
            if (num.empty()) return false;
            try { 
                int n = stoi(num); 
                return n >= 0 && n < 32; 
            } catch(...) {}
        }
        return false;
    }
    
    bool is_f64(const string &s) {
        if (s.size() < 4) return false;
        if (s.rfind("f64", 0) == 0) {
            string num;
            if (s.size() > 3 && s[3] == '_') num = s.substr(4);
            else num = s.substr(3);
            if (num.empty()) return false;
            try { 
                int n = stoi(num); 
                return n >= 0 && n < 32; 
            } catch(...) {}
        }
        return false;
    }

    int get_f32_index(const string &s) {
        if (!is_f32(s)) throw runtime_error("not an f32 register: " + s);
        if (s[3] == '_') return stoi(s.substr(4));
        return stoi(s.substr(3));
    }
    
    int get_f64_index(const string &s) {
        if (!is_f64(s)) throw runtime_error("not an f64 register: " + s);
        if (s[3] == '_') return stoi(s.substr(4));
        return stoi(s.substr(3));
    }
    
    bool is_float_literal(const string &s) {
        if (s.empty()) return false;
        try {
            stof(s);
            return s.find('.') != string::npos || s.find('e') != string::npos || s.find('E') != string::npos;
        } catch(...) {}
        return false;
    }
    
    float parse_float(const string &s) {
        try {
            return stof(s);
        } catch(...) {
            throw runtime_error("invalid float: " + s);
        }
    }
    
    void set_float_flags(float result) {
        FZ = (result == 0.0f);
        FN = (result < 0.0f);
    }
    
    void set_float_compare_flags(float a, float b) {
        FE = (a == b);
        FG = (a > b);
        FL = (a < b);
        FZ = FE;
        FN = FL;
    }

    bool is_mem(const string &s) {
        return s.size() >= 3 && s.front() == '[' && s.back() == ']';
    }

    bool is_number(const string &s) {
        if (s.empty()) return false;
        try {
            if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                stoi(s, nullptr, 16);
            } else {
                stoi(s, nullptr, 0);
            }
            return true;
        } catch(...) {}
        return false;
    }

    int parse_int(const string &tok) {
        try {
            if (tok.size() > 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X')) 
                return stoi(tok, nullptr, 16);
            return stoi(tok, nullptr, 0);
        } catch(...) { 
            throw runtime_error("invalid integer: " + tok); 
        }
    }

    int get_r8_index(const string &s) {
        if (!is_r8(s)) throw runtime_error("not an r8 register: " + s);
        if (s[2] == '_') return stoi(s.substr(3));
        return stoi(s.substr(2));
    }

    int get_r16_index(const string &s) {
        if (!is_r16(s)) throw runtime_error("not an r16 register: " + s);
        if (s[3] == '_') return stoi(s.substr(4));
        return stoi(s.substr(3));
    }

    u32 resolve_address(const string &memtok) {
        if (!is_mem(memtok)) throw runtime_error("not memory token: " + memtok);
        string inside = memtok.substr(1, memtok.size() - 2);
        inside = trim(inside);
        
        if (is_r8(inside)) {
            return regs8[get_r8_index(inside)];
        } else if (is_r16(inside)) {
            return regs16[get_r16_index(inside)];
        } else if (is_number(inside)) {
            int v = parse_int(inside);
            if (v < 0) throw runtime_error("negative address not supported");
            return (u32)v;
        } else {
            throw runtime_error("unsupported memory address token: " + inside);
        }
    }

    u8 mem_read8_at(u32 addr) {
        if (addr >= mem_size) throw runtime_error("memory read8 out of bounds at address " + to_string(addr));
        return mem[addr];
    }

    void mem_write8_at(u32 addr, u8 val) {
        if (addr >= mem_size) throw runtime_error("memory write8 out of bounds at address " + to_string(addr));
        mem[addr] = val;
    }

    u16 mem_read16_at(u32 addr) {
        if (addr + 1 >= mem_size) throw runtime_error("memory read16 out of bounds at address " + to_string(addr));
        return (u16)mem[addr] | ((u16)mem[addr + 1] << 8);
    }

    void mem_write16_at(u32 addr, u16 val) {
        if (addr + 1 >= mem_size) throw runtime_error("memory write16 out of bounds at address " + to_string(addr));
        mem[addr] = (u8)(val & 0xFF);
        mem[addr + 1] = (u8)((val >> 8) & 0xFF);
    }

    void run() {
        preprocess_labels();
        size_t pc = 0;
        
        while (pc < program.size()) {
            while (interrupt_enabled && !pending_interrupts.empty()) {
                u8 int_num = pending_interrupts.front();
                pending_interrupts.pop();
                handle_interrupt(int_num, pc);
            }

            string line = trim(program[pc]);

            if (line.empty() || line[0] == '#' || line.back() == ':') {
                pc++;
                continue;
            }

            // Only increment timer when NOT in interrupt handler
            if (interrupt_depth == 0 && timer_enabled && timer_interval > 0) {
                timer_counter++;
                if (timer_counter >= timer_interval) {
                    timer_counter = 0;
                    u8 timer_int = (u8)interrupt_vector_table[255];
                    trigger_interrupt(timer_int);
                }
            }

            if (interrupt_depth == 0) {
                for (size_t i = 0; i < pending_io.size(); ) {
                    pending_io[i].cycles_remaining--;
                    if (pending_io[i].cycles_remaining == 0) {
                        trigger_interrupt(pending_io[i].interrupt_num);
                        pending_io.erase(pending_io.begin() + i);
                    } else {
                        i++;
                    }
                }
            }

            auto toks = split_tok(line);
            if (toks.empty()) {
                pc++;
                continue;
            }

            string op = toks[0];

            // QUIT / EXIT
            if (op == "QUIT" || op == "EXIT") {
                // Process any remaining pending interrupts before exiting
                bool old_int_state = interrupt_enabled;
                interrupt_enabled = true;
                while (!pending_interrupts.empty()) {
                    u8 int_num = pending_interrupts.front();
                    pending_interrupts.pop();
                    interrupt_enabled = true;
                    handle_interrupt(int_num, pc);
                }
                interrupt_enabled = old_int_state;
                cout << "Program exited via QUIT.\n";
                return;
            }

            pc++; 

            if (op == "NOP") {
                // Literally do nothing
                continue;
            }

            if (op == "STI") {
                interrupt_enabled = true;
                continue;
            }

            if (op == "CLI") {
                interrupt_enabled = false;
                continue;
            }

            if (op == "INT") {
                if (toks.size() < 2) throw runtime_error("INT needs 1 argument (interrupt number)");
                string int_str = toks[1];
    
                u8 int_num = 0;
                if (is_r8(int_str)) int_num = regs8[get_r8_index(int_str)];
                else if (is_number(int_str)) int_num = (u8)parse_int(int_str);
                else throw runtime_error("INT: interrupt number must be r8 or immediate");
    
                // Trigger interrupt immediately
                handle_interrupt(int_num, pc);
                continue;
            }

            if (op == "IRET") {
                if (SP > stack_base + stack_size - 4) throw runtime_error("stack underflow during IRET");
    
                // Pop flags
                u16 flags = mem_read16_at(SP);
                SP += 2;
    
                // Restore flags
                ZF = (flags & (1 << 0)) != 0;
                SF = (flags & (1 << 1)) != 0;
                CF = (flags & (1 << 2)) != 0;
                OF = (flags & (1 << 3)) != 0;
                interrupt_enabled = (flags & (1 << 4)) != 0;
                trap_flag = (flags & (1 << 5)) != 0;
                
                // Pop return address
                u16 ret_addr = mem_read16_at(SP);
                SP += 2;

                interrupt_depth--;
                
                pc = ret_addr;
                continue;
            }

            if (op == "HLT") {
                // Real HLT: Stop execution until an interrupt occurs
                // Process any pending interrupt to wake from halt
                if (!pending_interrupts.empty()) {
                    u8 int_num = pending_interrupts.front();
                    pending_interrupts.pop();
                    handle_interrupt(int_num, pc);
                } else {
                    // No interrupts - CPU stays halted (program ends)
                    cout << "CPU halted. No interrupts available.\n";
                    return;
                }
                continue;
            }

            if (op == "SETVEC") {
                if (toks.size() < 3) throw runtime_error("SETVEC needs 2 arguments: interrupt_number handler_address");
                string int_str = toks[1], addr_str = toks[2];
    
                u8 int_num = 0;
                if (is_r8(int_str)) int_num = regs8[get_r8_index(int_str)];
                else if (is_number(int_str)) int_num = (u8)parse_int(int_str);
                else throw runtime_error("SETVEC: interrupt number must be r8 or immediate");
                
                u32 handler_addr = 0;
                if (is_r16(addr_str)) handler_addr = regs16[get_r16_index(addr_str)];
                else if (is_number(addr_str)) handler_addr = parse_int(addr_str);
                else if (labels.count(addr_str)) handler_addr = labels[addr_str];
                else throw runtime_error("SETVEC: handler address must be r16, immediate, or label");
    
                register_interrupt_handler(int_num, handler_addr);
                continue;
            }

            if (op == "TRIGGER") {
                if (toks.size() < 2) throw runtime_error("TRIGGER needs 1 argument");
                string int_str = toks[1];
    
                u8 int_num = 0;
                if (is_r8(int_str)) int_num = regs8[get_r8_index(int_str)];
                else if (is_number(int_str)) int_num = (u8)parse_int(int_str);
                else throw runtime_error("TRIGGER: interrupt number must be r8 or immediate");
    
                trigger_interrupt(int_num);
                continue;
            }

            // SETTIMER - Set timer interrupt interval
            // Syntax: SETTIMER interval_in_cycles interrupt_number
            if (op == "SETTIMER") {
                if (toks.size() < 3) throw runtime_error("SETTIMER needs 2 arguments: interval interrupt_num");
                
                string interval_str = toks[1];
                string int_str = toks[2];
    
                // Parse interval
                if (is_r16(interval_str)) timer_interval = regs16[get_r16_index(interval_str)];
                else if (is_number(interval_str)) timer_interval = parse_int(interval_str);
                else throw runtime_error("SETTIMER: interval must be r16 or immediate");
                
                // Parse interrupt number
                u8 int_num = 0;
                if (is_r8(int_str)) int_num = regs8[get_r8_index(int_str)];
                else if (is_number(int_str)) int_num = (u8)parse_int(int_str);
                else throw runtime_error("SETTIMER: interrupt number must be r8 or immediate");
                
                if (timer_interval > 0) {
                    timer_enabled = true;
                    timer_counter = 0;
                    // Store which interrupt to trigger (reuse interrupt_vector_table for config)
                    interrupt_vector_table[255] = int_num;  // Use slot 255 for timer config
                    cout << "Timer enabled: " << timer_interval << " cycles, interrupt " << (int)int_num << "\n";
                } else {
                    timer_enabled = false;
                    cout << "Timer disabled\n";
                }
                continue;
            }
            
            // STOPTIMER - Disable timer interrupts
            if (op == "STOPTIMER") {
                timer_enabled = false;
                timer_counter = 0;
                cout << "Timer stopped\n";
                continue;
            }
            
            // SCHEDIO - Schedule an I/O operation that will complete after N cycles
            // Syntax: SCHEDIO cycles interrupt_num
            // Simulates async I/O (disk read, network packet arrival, etc.)
            if (op == "SCHEDIO") {
                if (toks.size() < 3) throw runtime_error("SCHEDIO needs 2 arguments: cycles interrupt_num");
                
                u32 cycles = 0;
                if (is_r16(toks[1])) cycles = regs16[get_r16_index(toks[1])];
                else if (is_number(toks[1])) cycles = parse_int(toks[1]);
                else throw runtime_error("SCHEDIO: cycles must be r16 or immediate");
                
                u8 int_num = 0;
                if (is_r8(toks[2])) int_num = regs8[get_r8_index(toks[2])];
                else if (is_number(toks[2])) int_num = (u8)parse_int(toks[2]);
                else throw runtime_error("SCHEDIO: interrupt number must be r8 or immediate");
                
                pending_io.push_back({int_num, cycles});
                cout << "I/O scheduled: " << cycles << " cycles, interrupt " << (int)int_num << "\n";
                continue;
            }

            // STORE - Store 8-bit value to memory
            // Syntax: STORE src, dest_addr
            if (op == "STORE") {
                if (toks.size() < 3) throw runtime_error("STORE needs 2 arguments (value, address)");
                string src = toks[1];
                string dest = toks[2];
                
                u8 value = 0;
                // Get source value
                if (is_r8(src)) {
                    value = regs8[get_r8_index(src)];
                } else if (is_number(src)) {
                    value = (u8)(parse_int(src) & 0xFF);
                } else {
                    throw runtime_error("STORE: source must be r8 register or immediate");
                }
                
                // Get destination address
                u32 addr = 0;
                if (is_r16(dest)) {
                    addr = regs16[get_r16_index(dest)];
                } else if (is_number(dest)) {
                    addr = parse_int(dest);
                } else if (is_mem(dest)) {
                    addr = resolve_address(dest);
                } else {
                    throw runtime_error("STORE: destination must be r16, immediate, or memory address");
                }
                
                mem_write8_at(addr, value);
                continue;
            }
            
            // HSTORE - Store 16-bit value to memory
            // Syntax: HSTORE src, dest_addr
            if (op == "HSTORE") {
                if (toks.size() < 3) throw runtime_error("HSTORE needs 2 arguments (value, address)");
                string src = toks[1];
                string dest = toks[2];
                
                u16 value = 0;
                // Get source value
                if (is_r16(src)) {
                    value = regs16[get_r16_index(src)];
                } else if (is_number(src)) {
                    value = (u16)(parse_int(src) & 0xFFFF);
                } else {
                    throw runtime_error("HSTORE: source must be r16 register or immediate");
                }
                
                // Get destination address
                u32 addr = 0;
                if (is_r16(dest)) {
                    addr = regs16[get_r16_index(dest)];
                } else if (is_number(dest)) {
                    addr = parse_int(dest);
                } else if (is_mem(dest)) {
                    addr = resolve_address(dest);
                } else {
                    throw runtime_error("HSTORE: destination must be r16, immediate, or memory address");
                }
                
                mem_write16_at(addr, value);
                continue;
            }

            // float-point instructions
            if (op == "FMOV") {
                if (toks.size() < 3) throw runtime_error("FMOV needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                float val = 0.0f;
                
                // Get source value
                if (is_f32(src)) {
                    val = regs_f32[get_f32_index(src)];
                } else if (is_float_literal(src)) {
                    val = parse_float(src);
                } else if (is_mem(src)) {
                    u32 addr = resolve_address(src);
                    u32 bits = mem_read16_at(addr) | ((u32)mem_read16_at(addr + 2) << 16);
                    memcpy(&val, &bits, sizeof(float));
                } else {
                    throw runtime_error("FMOV: unsupported source");
                }
                
                // Write to destination
                if (is_f32(dst)) {
                    regs_f32[get_f32_index(dst)] = val;
                } else if (is_mem(dst)) {
                    u32 addr = resolve_address(dst);
                    u32 bits;
                    memcpy(&bits, &val, sizeof(float));
                    mem_write16_at(addr, bits & 0xFFFF);
                    mem_write16_at(addr + 2, (bits >> 16) & 0xFFFF);
                } else {
                    throw runtime_error("FMOV: unsupported destination");
                }
                continue;
            }

            // DMOV - Move 64-bit double
            // Syntax: DMOV source destination
            if (op == "DMOV") {
                if (toks.size() < 3) throw runtime_error("DMOV needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                double val = 0.0;
                
                // Get source value
                if (is_f64(src)) {
                    val = regs_f64[get_f64_index(src)];
                } else if (is_float_literal(src)) {
                    val = stod(src);
                } else if (is_mem(src)) {
                    u32 addr = resolve_address(src);
                    u64 bits = 0;
                    bits = mem_read16_at(addr) | 
                           ((u64)mem_read16_at(addr + 2) << 16) | 
                           ((u64)mem_read16_at(addr + 4) << 32) | 
                           ((u64)mem_read16_at(addr + 6) << 48);
                    memcpy(&val, &bits, sizeof(double));
                } else {
                    throw runtime_error("DMOV: unsupported source");
                }
                
                // Write to destination
                if (is_f64(dst)) {
                    regs_f64[get_f64_index(dst)] = val;
                } else if (is_mem(dst)) {
                    u32 addr = resolve_address(dst);
                    u64 bits;
                    memcpy(&bits, &val, sizeof(double));
                    mem_write16_at(addr, bits & 0xFFFF);
                    mem_write16_at(addr + 2, (bits >> 16) & 0xFFFF);
                    mem_write16_at(addr + 4, (bits >> 32) & 0xFFFF);
                    mem_write16_at(addr + 6, (bits >> 48) & 0xFFFF);
                } else {
                    throw runtime_error("DMOV: unsupported destination");
                }
                continue;
            }

            if (op == "FADD") {
                if (toks.size() < 3) throw runtime_error("FADD needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                float aval = 0.0f;
                if (is_f32(A)) aval = regs_f32[get_f32_index(A)];
                else if (is_float_literal(A)) aval = parse_float(A);
                else throw runtime_error("FADD: first operand must be f32 or float literal");
                
                if (!is_f32(B)) throw runtime_error("FADD: second operand must be f32 register");
                int bi = get_f32_index(B);
                regs_f32[bi] += aval;
                set_float_flags(regs_f32[bi]);
                continue;
            }

            // DADD - Double Add
            // Syntax: DADD operand1 operand2 (B = B + A)
            if (op == "DADD") {
                if (toks.size() < 3) throw runtime_error("DADD needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                double aval = 0.0;
                if (is_f64(A)) aval = regs_f64[get_f64_index(A)];
                else if (is_float_literal(A)) aval = stod(A);
                else throw runtime_error("DADD: first operand must be f64 or float literal");
                
                if (!is_f64(B)) throw runtime_error("DADD: second operand must be f64 register");
                int bi = get_f64_index(B);
                regs_f64[bi] += aval;
                continue;
            }
            
            // FSUB - Float Subtract
            // Syntax: FSUB operand1 operand2 (B = B - A)
            if (op == "FSUB") {
                if (toks.size() < 3) throw runtime_error("FSUB needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                float aval = 0.0f;
                if (is_f32(A)) aval = regs_f32[get_f32_index(A)];
                else if (is_float_literal(A)) aval = parse_float(A);
                else throw runtime_error("FSUB: first operand must be f32 or float literal");
                
                if (!is_f32(B)) throw runtime_error("FSUB: second operand must be f32 register");
                int bi = get_f32_index(B);
                regs_f32[bi] -= aval;
                set_float_flags(regs_f32[bi]);
                continue;
            }

            // DSUB - Double Subtract
            // Syntax: DSUB operand1 operand2 (B = B - A)
            if (op == "DSUB") {
                if (toks.size() < 3) throw runtime_error("DSUB needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                double aval = 0.0;
                if (is_f64(A)) aval = regs_f64[get_f64_index(A)];
                else if (is_float_literal(A)) aval = stod(A);
                else throw runtime_error("DSUB: first operand must be f64 or float literal");
                
                if (!is_f64(B)) throw runtime_error("DSUB: second operand must be f64 register");
                int bi = get_f64_index(B);
                regs_f64[bi] -= aval;
                continue;
            }
            
            // FMUL - Float Multiply
            // Syntax: FMUL operand1 operand2
            if (op == "FMUL") {
                if (toks.size() < 3) throw runtime_error("FMUL needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                float aval = 0.0f;
                if (is_f32(A)) aval = regs_f32[get_f32_index(A)];
                else if (is_float_literal(A)) aval = parse_float(A);
                else throw runtime_error("FMUL: first operand must be f32 or float literal");
                
                if (!is_f32(B)) throw runtime_error("FMUL: second operand must be f32 register");
                int bi = get_f32_index(B);
                regs_f32[bi] *= aval;
                set_float_flags(regs_f32[bi]);
                continue;
            }

            // DMUL - Double Multiply
            // Syntax: DMUL operand1 operand2 (B = B * A)
            if (op == "DMUL") {
                if (toks.size() < 3) throw runtime_error("DMUL needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                double aval = 0.0;
                if (is_f64(A)) aval = regs_f64[get_f64_index(A)];
                else if (is_float_literal(A)) aval = stod(A);
                else throw runtime_error("DMUL: first operand must be f64 or float literal");
                
                if (!is_f64(B)) throw runtime_error("DMUL: second operand must be f64 register");
                int bi = get_f64_index(B);
                regs_f64[bi] *= aval;
                continue;
            }
            
            // FDIV - Float Divide
            // Syntax: FDIV operand1 operand2 (B = B / A)
            if (op == "FDIV") {
                if (toks.size() < 3) throw runtime_error("FDIV needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                float aval = 0.0f;
                if (is_f32(A)) aval = regs_f32[get_f32_index(A)];
                else if (is_float_literal(A)) aval = parse_float(A);
                else throw runtime_error("FDIV: first operand must be f32 or float literal");
                
                if (aval == 0.0f) throw runtime_error("floating point division by zero");
                
                if (!is_f32(B)) throw runtime_error("FDIV: second operand must be f32 register");
                int bi = get_f32_index(B);
                regs_f32[bi] /= aval;
                set_float_flags(regs_f32[bi]);
                continue;
            }

            // DDIV - Double Divide
            // Syntax: DDIV operand1 operand2 (B = B / A)
            if (op == "DDIV") {
                if (toks.size() < 3) throw runtime_error("DDIV needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                double aval = 0.0;
                if (is_f64(A)) aval = regs_f64[get_f64_index(A)];
                else if (is_float_literal(A)) aval = stod(A);
                else throw runtime_error("DDIV: first operand must be f64 or float literal");
                
                if (aval == 0.0) {
                    OF = true;
                    cout << "WARNING: Double division by zero\n";
                    continue;
                }
                
                if (!is_f64(B)) throw runtime_error("DDIV: second operand must be f64 register");
                int bi = get_f64_index(B);
                regs_f64[bi] /= aval;
                continue;
            }
            
            // FCMP - Float Compare
            // Syntax: FCMP operand1 operand2
            if (op == "FCMP") {
                if (toks.size() < 3) throw runtime_error("FCMP needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                float aval = 0.0f, bval = 0.0f;
                
                if (is_f32(A)) aval = regs_f32[get_f32_index(A)];
                else if (is_float_literal(A)) aval = parse_float(A);
                else throw runtime_error("FCMP: first operand must be f32 or float literal");
                
                if (is_f32(B)) bval = regs_f32[get_f32_index(B)];
                else if (is_float_literal(B)) bval = parse_float(B);
                else throw runtime_error("FCMP: second operand must be f32 or float literal");
                
                set_float_compare_flags(aval, bval);
                continue;
            }

            // DCMP - Double Compare
            // Syntax: DCMP operand1 operand2
            if (op == "DCMP") {
                if (toks.size() < 3) throw runtime_error("DCMP needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                double aval = 0.0, bval = 0.0;
                
                if (is_f64(A)) aval = regs_f64[get_f64_index(A)];
                else if (is_float_literal(A)) aval = stod(A);
                else throw runtime_error("DCMP: first operand must be f64 or float literal");
                
                if (is_f64(B)) bval = regs_f64[get_f64_index(B)];
                else if (is_float_literal(B)) bval = stod(B);
                else throw runtime_error("DCMP: second operand must be f64 or float literal");
                
                FE = (aval == bval);
                FG = (aval > bval);
                FL = (aval < bval);
                FZ = FE;
                FN = FL;
                continue;
            }
            
            // FSQRT - Float Square Root
            // Syntax: FSQRT operand
            if (op == "FSQRT") {
                if (toks.size() < 2) throw runtime_error("FSQRT needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FSQRT: operand must be f32 register");
                int idx = get_f32_index(A);
                
                if (regs_f32[idx] < 0.0f) throw runtime_error("FSQRT: square root of negative number");
                
                regs_f32[idx] = sqrtf(regs_f32[idx]);
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DSQRT - Double Square Root
            // Syntax: DSQRT operand
            if (op == "DSQRT") {
                if (toks.size() < 2) throw runtime_error("DSQRT needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DSQRT: operand must be f64 register");
                int idx = get_f64_index(A);
                
                if (regs_f64[idx] < 0.0) throw runtime_error("DSQRT: square root of negative number");
                
                regs_f64[idx] = sqrt(regs_f64[idx]);
                continue;
            }
            
            // FABS - Float Absolute Value
            // Syntax: FABS operand
            if (op == "FABS") {
                if (toks.size() < 2) throw runtime_error("FABS needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FABS: operand must be f32 register");
                int idx = get_f32_index(A);
                regs_f32[idx] = fabsf(regs_f32[idx]);
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DABS - Double Absolute Value
            // Syntax: DABS operand
            if (op == "DABS") {
                if (toks.size() < 2) throw runtime_error("DABS needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DABS: operand must be f64 register");
                int idx = get_f64_index(A);
                regs_f64[idx] = fabs(regs_f64[idx]);
                continue;
            }
            
            // FNEG - Float Negate
            // Syntax: FNEG operand
            if (op == "FNEG") {
                if (toks.size() < 2) throw runtime_error("FNEG needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FNEG: operand must be f32 register");
                int idx = get_f32_index(A);
                regs_f32[idx] = -regs_f32[idx];
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DNEG - Double Negate
            // Syntax: DNEG operand
            if (op == "DNEG") {
                if (toks.size() < 2) throw runtime_error("DNEG needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DNEG: operand must be f64 register");
                int idx = get_f64_index(A);
                regs_f64[idx] = -regs_f64[idx];
                continue;
            }
            
            // FSIN - Float Sine
            // Syntax: FSIN operand
            if (op == "FSIN") {
                if (toks.size() < 2) throw runtime_error("FSIN needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FSIN: operand must be f32 register");
                int idx = get_f32_index(A);
                regs_f32[idx] = sinf(regs_f32[idx]);
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DSIN - Double Sine
            // Syntax: DSIN operand
            if (op == "DSIN") {
                if (toks.size() < 2) throw runtime_error("DSIN needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DSIN: operand must be f64 register");
                int idx = get_f64_index(A);
                regs_f64[idx] = sin(regs_f64[idx]);
                continue;
            }
            
            // FCOS - Float Cosine
            // Syntax: FCOS operand
            if (op == "FCOS") {
                if (toks.size() < 2) throw runtime_error("FCOS needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FCOS: operand must be f32 register");
                int idx = get_f32_index(A);
                regs_f32[idx] = cosf(regs_f32[idx]);
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DCOS - Double Cosine
            // Syntax: DCOS operand
            if (op == "DCOS") {
                if (toks.size() < 2) throw runtime_error("DCOS needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DCOS: operand must be f64 register");
                int idx = get_f64_index(A);
                regs_f64[idx] = cos(regs_f64[idx]);
                continue;
            }
            
            // FTAN - Float Tangent
            // Syntax: FTAN operand
            if (op == "FTAN") {
                if (toks.size() < 2) throw runtime_error("FTAN needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FTAN: operand must be f32 register");
                int idx = get_f32_index(A);
                regs_f32[idx] = tanf(regs_f32[idx]);
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DTAN - Double Tangent
            // Syntax: DTAN operand
            if (op == "DTAN") {
                if (toks.size() < 2) throw runtime_error("DTAN needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DTAN: operand must be f64 register");
                int idx = get_f64_index(A);
                regs_f64[idx] = tan(regs_f64[idx]);
                continue;
            }
            
            // FPOW - Float Power
            // Syntax: FPOW base exponent (exponent = base ^ exponent)
            if (op == "FPOW") {
                if (toks.size() < 3) throw runtime_error("FPOW needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                float aval = 0.0f;
                if (is_f32(A)) aval = regs_f32[get_f32_index(A)];
                else if (is_float_literal(A)) aval = parse_float(A);
                else throw runtime_error("FPOW: base must be f32 or float literal");
                
                if (!is_f32(B)) throw runtime_error("FPOW: exponent must be f32 register");
                int bi = get_f32_index(B);
                regs_f32[bi] = powf(aval, regs_f32[bi]);
                set_float_flags(regs_f32[bi]);
                continue;
            }

            // DPOW - Double Power
            // Syntax: DPOW base exponent (exponent = base ^ exponent)
            if (op == "DPOW") {
                if (toks.size() < 3) throw runtime_error("DPOW needs 2 arguments");
                string A = toks[1], B = toks[2];
                
                double aval = 0.0;
                if (is_f64(A)) aval = regs_f64[get_f64_index(A)];
                else if (is_float_literal(A)) aval = stod(A);
                else throw runtime_error("DPOW: base must be f64 or float literal");
                
                if (!is_f64(B)) throw runtime_error("DPOW: exponent must be f64 register");
                int bi = get_f64_index(B);
                regs_f64[bi] = pow(aval, regs_f64[bi]);
                continue;
            }
            
            // FLOG - Float Natural Logarithm
            // Syntax: FLOG operand
            if (op == "FLOG") {
                if (toks.size() < 2) throw runtime_error("FLOG needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FLOG: operand must be f32 register");
                int idx = get_f32_index(A);
                
                if (regs_f32[idx] <= 0.0f) throw runtime_error("FLOG: logarithm of non-positive number");
                
                regs_f32[idx] = logf(regs_f32[idx]);
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DLOG - Double Natural Logarithm
            // Syntax: DLOG operand
            if (op == "DLOG") {
                if (toks.size() < 2) throw runtime_error("DLOG needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DLOG: operand must be f64 register");
                int idx = get_f64_index(A);
                
                if (regs_f64[idx] <= 0.0) throw runtime_error("DLOG: logarithm of non-positive number");
                
                regs_f64[idx] = log(regs_f64[idx]);
                continue;
            }
            
            // FEXP - Float Exponential (e^x)
            // Syntax: FEXP operand
            if (op == "FEXP") {
                if (toks.size() < 2) throw runtime_error("FEXP needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FEXP: operand must be f32 register");
                int idx = get_f32_index(A);
                regs_f32[idx] = expf(regs_f32[idx]);
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DEXP - Double Exponential (e^x)
            // Syntax: DEXP operand
            if (op == "DEXP") {
                if (toks.size() < 2) throw runtime_error("DEXP needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DEXP: operand must be f64 register");
                int idx = get_f64_index(A);
                regs_f64[idx] = exp(regs_f64[idx]);
                continue;
            }
            
            // FFLOOR - Float Floor
            // Syntax: FFLOOR operand
            if (op == "FFLOOR") {
                if (toks.size() < 2) throw runtime_error("FFLOOR needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FFLOOR: operand must be f32 register");
                int idx = get_f32_index(A);
                regs_f32[idx] = floorf(regs_f32[idx]);
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DFLOOR - Double Floor
            // Syntax: DFLOOR operand
            if (op == "DFLOOR") {
                if (toks.size() < 2) throw runtime_error("DFLOOR needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DFLOOR: operand must be f64 register");
                int idx = get_f64_index(A);
                regs_f64[idx] = floor(regs_f64[idx]);
                continue;
            }
            
            // FCEIL - Float Ceiling
            // Syntax: FCEIL operand
            if (op == "FCEIL") {
                if (toks.size() < 2) throw runtime_error("FCEIL needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FCEIL: operand must be f32 register");
                int idx = get_f32_index(A);
                regs_f32[idx] = ceilf(regs_f32[idx]);
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DCEIL - Double Ceiling
            // Syntax: DCEIL operand
            if (op == "DCEIL") {
                if (toks.size() < 2) throw runtime_error("DCEIL needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DCEIL: operand must be f64 register");
                int idx = get_f64_index(A);
                regs_f64[idx] = ceil(regs_f64[idx]);
                continue;
            }
            
            // FROUND - Float Round to Nearest
            // Syntax: FROUND operand
            if (op == "FROUND") {
                if (toks.size() < 2) throw runtime_error("FROUND needs 1 argument");
                string A = toks[1];
                
                if (!is_f32(A)) throw runtime_error("FROUND: operand must be f32 register");
                int idx = get_f32_index(A);
                regs_f32[idx] = roundf(regs_f32[idx]);
                set_float_flags(regs_f32[idx]);
                continue;
            }

            // DROUND - Double Round to Nearest
            // Syntax: DROUND operand
            if (op == "DROUND") {
                if (toks.size() < 2) throw runtime_error("DROUND needs 1 argument");
                string A = toks[1];
                
                if (!is_f64(A)) throw runtime_error("DROUND: operand must be f64 register");
                int idx = get_f64_index(A);
                regs_f64[idx] = round(regs_f64[idx]);
                continue;
            }
            
            // ITOF - Integer to Float conversion
            // Syntax: ITOF int_source float_dest
            if (op == "ITOF") {
                if (toks.size() < 3) throw runtime_error("ITOF needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                int ival = 0;
                if (is_r8(src)) ival = (i8)regs8[get_r8_index(src)];  // Signed conversion
                else if (is_r16(src)) ival = (i16)regs16[get_r16_index(src)];
                else if (is_number(src)) ival = parse_int(src);
                else throw runtime_error("ITOF: source must be integer register or literal");
                
                if (!is_f32(dst)) throw runtime_error("ITOF: destination must be f32 register");
                regs_f32[get_f32_index(dst)] = (float)ival;
                continue;
            }

            // ITOD - Integer to Double conversion
            // Syntax: ITOD int_source double_dest
            if (op == "ITOD") {
                if (toks.size() < 3) throw runtime_error("ITOD needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                int ival = 0;
                if (is_r8(src)) ival = (i8)regs8[get_r8_index(src)];
                else if (is_r16(src)) ival = (i16)regs16[get_r16_index(src)];
                else if (is_number(src)) ival = parse_int(src);
                else throw runtime_error("ITOD: source must be integer register or literal");
                
                if (!is_f64(dst)) throw runtime_error("ITOD: destination must be f64 register");
                regs_f64[get_f64_index(dst)] = (double)ival;
                continue;
            }
            
            // FTOI - Float to Integer conversion (truncates)
            // Syntax: FTOI float_source int_dest
            if (op == "FTOI") {
                if (toks.size() < 3) throw runtime_error("FTOI needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                if (!is_f32(src)) throw runtime_error("FTOI: source must be f32 register");
                float fval = regs_f32[get_f32_index(src)];
                int ival = (int)fval;  // Truncate towards zero
                
                if (is_r8(dst)) regs8[get_r8_index(dst)] = (u8)ival;
                else if (is_r16(dst)) regs16[get_r16_index(dst)] = (u16)ival;
                else throw runtime_error("FTOI: destination must be integer register");
                continue;
            }

            // FTOD - Float to Double conversion
            // Syntax: FTOD f32_source f64_dest
            if (op == "FTOD") {
                if (toks.size() < 3) throw runtime_error("FTOD needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                if (!is_f32(src)) throw runtime_error("FTOD: source must be f32 register");
                if (!is_f64(dst)) throw runtime_error("FTOD: destination must be f64 register");
                
                regs_f64[get_f64_index(dst)] = (double)regs_f32[get_f32_index(src)];
                continue;
            }

            // DTOI - Double to Integer conversion (truncates)
            // Syntax: DTOI double_source int_dest
            if (op == "DTOI") {
                if (toks.size() < 3) throw runtime_error("DTOI needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                if (!is_f64(src)) throw runtime_error("DTOI: source must be f64 register");
                double dval = regs_f64[get_f64_index(src)];
                int ival = (int)dval;
                
                if (is_r8(dst)) regs8[get_r8_index(dst)] = (u8)ival;
                else if (is_r16(dst)) regs16[get_r16_index(dst)] = (u16)ival;
                else throw runtime_error("DTOI: destination must be integer register");
                continue;
            }

            // DTOF - Double to Float conversion
            // Syntax: DTOF f64_source f32_dest
            if (op == "DTOF") {
                if (toks.size() < 3) throw runtime_error("DTOF needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                if (!is_f64(src)) throw runtime_error("DTOF: source must be f64 register");
                if (!is_f32(dst)) throw runtime_error("DTOF: destination must be f32 register");
                
                regs_f32[get_f32_index(dst)] = (float)regs_f64[get_f64_index(src)];
                continue;
            }
            
            // Float conditional jumps
            if (op == "JFE") {  // Jump if Float Equal
                if (toks.size() < 2) throw runtime_error("JFE needs a label");
                if (FE) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }
            
            if (op == "JFNE") {  // Jump if Float Not Equal
                if (toks.size() < 2) throw runtime_error("JFNE needs a label");
                if (!FE) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }
            
            if (op == "JFG") {  // Jump if Float Greater
                if (toks.size() < 2) throw runtime_error("JFG needs a label");
                if (FG) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }
            
            if (op == "JFGE") {  // Jump if Float Greater or Equal
                if (toks.size() < 2) throw runtime_error("JFGE needs a label");
                if (FG || FE) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }
            
            if (op == "JFL") {  // Jump if Float Less
                if (toks.size() < 2) throw runtime_error("JFL needs a label");
                if (FL) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }
            
            if (op == "JFLE") {  // Jump if Float Less or Equal
                if (toks.size() < 2) throw runtime_error("JFLE needs a label");
                if (FL || FE) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }
            
            // FPRINT - Print float value
            if (op == "FPRINT") {
                if (toks.size() < 2) throw runtime_error("FPRINT needs 1 argument");
                string A = toks[1];
                
                if (is_f32(A)) {
                    int idx = get_f32_index(A);
                    cout << A << " = " << regs_f32[idx] << "\n";
                } else {
                    throw runtime_error("FPRINT: argument must be f32 register");
                }
                continue;
            }

            // DPRINT - Print double value
            // Syntax: DPRINT operand
            if (op == "DPRINT") {
                if (toks.size() < 2) throw runtime_error("DPRINT needs 1 argument");
                string A = toks[1];
                
                if (is_f64(A)) {
                    int idx = get_f64_index(A);
                    cout << A << " = " << regs_f64[idx] << "\n";
                } else {
                    throw runtime_error("DPRINT: argument must be f64 register");
                }
                continue;
            }

            // CMOVE/CMOVZ - Conditional Move if Equal/Zero (ZF=1)
            // Syntax: CMOVE source destination
            if (op == "CMOVE" || op == "CMOVZ") {
                if (toks.size() < 3) throw runtime_error("CMOVE needs 2 arguments");
                if (!ZF) continue;  // Don't move if ZF not set
                
                string src = toks[1], dst = toks[2];
                int val = 0;
                bool is_16 = false;
                
                // Get source value
                if (is_r8(src)) val = regs8[get_r8_index(src)];
                else if (is_r16(src)) { val = regs16[get_r16_index(src)]; is_16 = true; }
                else if (is_mem(src)) val = mem_read8_at(resolve_address(src));
                else if (is_number(src)) val = parse_int(src);
                else throw runtime_error("CMOVE: unsupported source");
                
                // Write to destination
                if (is_r8(dst)) regs8[get_r8_index(dst)] = (u8)val;
                else if (is_r16(dst)) regs16[get_r16_index(dst)] = (u16)val;
                else if (is_mem(dst)) {
                    if (is_16) mem_write16_at(resolve_address(dst), (u16)val);
                    else mem_write8_at(resolve_address(dst), (u8)val);
                }
                else throw runtime_error("CMOVE: unsupported destination");
                
                continue;
            }

            // CMOVNE/CMOVNZ - Conditional Move if Not Equal/Not Zero (ZF=0)
            // Syntax: CMOVNE source destination
            if (op == "CMOVNE" || op == "CMOVNZ") {
                if (toks.size() < 3) throw runtime_error("CMOVNE needs 2 arguments");
                if (ZF) continue;  // Don't move if ZF set
                
                string src = toks[1], dst = toks[2];
                int val = 0;
                bool is_16 = false;
                
                if (is_r8(src)) val = regs8[get_r8_index(src)];
                else if (is_r16(src)) { val = regs16[get_r16_index(src)]; is_16 = true; }
                else if (is_mem(src)) val = mem_read8_at(resolve_address(src));
                else if (is_number(src)) val = parse_int(src);
                else throw runtime_error("CMOVNE: unsupported source");
                
                if (is_r8(dst)) regs8[get_r8_index(dst)] = (u8)val;
                else if (is_r16(dst)) regs16[get_r16_index(dst)] = (u16)val;
                else if (is_mem(dst)) {
                    if (is_16) mem_write16_at(resolve_address(dst), (u16)val);
                    else mem_write8_at(resolve_address(dst), (u8)val);
                }
                else throw runtime_error("CMOVNE: unsupported destination");
                
                continue;
            }

            // CMOVC - Conditional Move if Carry (CF=1)
            // Syntax: CMOVC source destination
            if (op == "CMOVC") {
                if (toks.size() < 3) throw runtime_error("CMOVC needs 2 arguments");
                if (!CF) continue;
                
                string src = toks[1], dst = toks[2];
                int val = 0;
                bool is_16 = false;
                
                if (is_r8(src)) val = regs8[get_r8_index(src)];
                else if (is_r16(src)) { val = regs16[get_r16_index(src)]; is_16 = true; }
                else if (is_mem(src)) val = mem_read8_at(resolve_address(src));
                else if (is_number(src)) val = parse_int(src);
                else throw runtime_error("CMOVC: unsupported source");
                
                if (is_r8(dst)) regs8[get_r8_index(dst)] = (u8)val;
                else if (is_r16(dst)) regs16[get_r16_index(dst)] = (u16)val;
                else if (is_mem(dst)) {
                    if (is_16) mem_write16_at(resolve_address(dst), (u16)val);
                    else mem_write8_at(resolve_address(dst), (u8)val);
                }
                else throw runtime_error("CMOVC: unsupported destination");
                
                continue;
            }

            // CMOVNC - Conditional Move if Not Carry (CF=0)
            // Syntax: CMOVNC source destination
            if (op == "CMOVNC") {
                if (toks.size() < 3) throw runtime_error("CMOVNC needs 2 arguments");
                if (CF) continue;
                
                string src = toks[1], dst = toks[2];
                int val = 0;
                bool is_16 = false;
                
                if (is_r8(src)) val = regs8[get_r8_index(src)];
                else if (is_r16(src)) { val = regs16[get_r16_index(src)]; is_16 = true; }
                else if (is_mem(src)) val = mem_read8_at(resolve_address(src));
                else if (is_number(src)) val = parse_int(src);
                else throw runtime_error("CMOVNC: unsupported source");
                
                if (is_r8(dst)) regs8[get_r8_index(dst)] = (u8)val;
                else if (is_r16(dst)) regs16[get_r16_index(dst)] = (u16)val;
                else if (is_mem(dst)) {
                    if (is_16) mem_write16_at(resolve_address(dst), (u16)val);
                    else mem_write8_at(resolve_address(dst), (u8)val);
                }
                else throw runtime_error("CMOVNC: unsupported destination");
                
                continue;
            }

            // CMOVS - Conditional Move if Sign (SF=1, negative)
            // Syntax: CMOVS source destination
            if (op == "CMOVS") {
                if (toks.size() < 3) throw runtime_error("CMOVS needs 2 arguments");
                if (!SF) continue;
                
                string src = toks[1], dst = toks[2];
                int val = 0;
                bool is_16 = false;
                
                if (is_r8(src)) val = regs8[get_r8_index(src)];
                else if (is_r16(src)) { val = regs16[get_r16_index(src)]; is_16 = true; }
                else if (is_mem(src)) val = mem_read8_at(resolve_address(src));
                else if (is_number(src)) val = parse_int(src);
                else throw runtime_error("CMOVS: unsupported source");
                
                if (is_r8(dst)) regs8[get_r8_index(dst)] = (u8)val;
                else if (is_r16(dst)) regs16[get_r16_index(dst)] = (u16)val;
                else if (is_mem(dst)) {
                    if (is_16) mem_write16_at(resolve_address(dst), (u16)val);
                    else mem_write8_at(resolve_address(dst), (u8)val);
                }
                else throw runtime_error("CMOVS: unsupported destination");
                
                continue;
            }

            // CMOVNS - Conditional Move if Not Sign (SF=0, positive)
            // Syntax: CMOVNS source destination
            if (op == "CMOVNS") {
                if (toks.size() < 3) throw runtime_error("CMOVNS needs 2 arguments");
                if (SF) continue;
                
                string src = toks[1], dst = toks[2];
                int val = 0;
                bool is_16 = false;
                
                if (is_r8(src)) val = regs8[get_r8_index(src)];
                else if (is_r16(src)) { val = regs16[get_r16_index(src)]; is_16 = true; }
                else if (is_mem(src)) val = mem_read8_at(resolve_address(src));
                else if (is_number(src)) val = parse_int(src);
                else throw runtime_error("CMOVNS: unsupported source");
                
                if (is_r8(dst)) regs8[get_r8_index(dst)] = (u8)val;
                else if (is_r16(dst)) regs16[get_r16_index(dst)] = (u16)val;
                else if (is_mem(dst)) {
                    if (is_16) mem_write16_at(resolve_address(dst), (u16)val);
                    else mem_write8_at(resolve_address(dst), (u8)val);
                }
                else throw runtime_error("CMOVNS: unsupported destination");
                
                continue;
            }

            // Arithmetic ops: LSADD, LUADD, HSADD, HUADD, etc.
            if ((op.size() == 5 || op.size() == 6) && 
                (op.find("ADD") != string::npos || op.find("SUB") != string::npos || 
                 op.find("MUL") != string::npos || op.find("DIV") != string::npos)) {
                
                char size = op[0];
                char sign = op[1];
                string body = op.substr(2);
                string opcode;
                
                if (body == "ADD" || body == "SUB" || body == "MUL" || body == "DIV") 
                    opcode = body;
                else 
                    opcode = body;

                if (toks.size() < 3) throw runtime_error("not enough args for arithmetic: " + op);
                string A = toks[1], B = toks[2];
                
                if (size == 'L') {
                    // 8-bit arithmetic
                    int aval = 0;
                    if (is_r8(A)) aval = (int)regs8[get_r8_index(A)];
                    else if (is_number(A)) aval = parse_int(A) & 0xFF;
                    else if (is_mem(A)) aval = mem_read8_at(resolve_address(A));
                    else throw runtime_error("unsupported A for 8-bit op: " + A);
                    
                    if (is_r8(B)) {
                        int bi = get_r8_index(B);
                        int bval = regs8[bi];
                        int result;
                        
                        if (opcode == "ADD") {
                            result = bval + aval;
                            regs8[bi] = (u8)result;
                            set_flags_add(aval, bval, result, false);
                        } else if (opcode == "SUB") {
                            result = bval - aval;
                            regs8[bi] = (u8)result;
                            set_flags_sub(aval, bval, result, false);
                        } else if (opcode == "MUL") {
                            // 8x8 = 16-bit result: low in bi, high in bi+1
                            if (sign == 'S') {
                                i16 full_result = (i8)bval * (i8)aval;
                                regs8[bi] = (u8)(full_result & 0xFF);
                                if (bi + 1 < 32) regs8[bi + 1] = (u8)((full_result >> 8) & 0xFF);
                            } else {
                                u16 full_result = (u8)bval * (u8)aval;
                                regs8[bi] = (u8)(full_result & 0xFF);
                                if (bi + 1 < 32) regs8[bi + 1] = (u8)((full_result >> 8) & 0xFF);
                            }
                        } else if (opcode == "DIV") {
                            if (aval == 0) {
                                // Division by zero - set error flag and continue
                                OF = true;  // Use overflow flag to signal error
                                ZF = true;
                                regs8[bi] = 0;  // Set result to 0
                                cout << "WARNING: Division by zero at instruction, result set to 0\n";
                            } else {
                                OF = false;
                                if (sign == 'S') {
                                    regs8[bi] = (u8)((i8)bval / (i8)aval);
                                    // Store remainder in bi+1 if available
                                    if (bi + 1 < 32) regs8[bi + 1] = (u8)((i8)bval % (i8)aval);
                                } else {
                                    regs8[bi] = (u8)((u8)bval / (u8)aval);
                                    // Store remainder in bi+1 if available
                                    if (bi + 1 < 32) regs8[bi + 1] = (u8)((u8)bval % (u8)aval);
                                }
                            }
                        }
                    } else if (is_mem(B)) {
                        u32 addr = resolve_address(B);
                        u8 bval = mem_read8_at(addr);
                        int result;
                        
                        if (opcode == "ADD") {
                            result = bval + aval;
                            mem_write8_at(addr, (u8)result);
                            set_flags_add(aval, bval, result, false);
                        } else if (opcode == "SUB") {
                            result = bval - aval;
                            mem_write8_at(addr, (u8)result);
                            set_flags_sub(aval, bval, result, false);
                        } else if (opcode == "MUL") {
                            // For memory, store low byte only (high byte lost)
                            if (sign == 'S') {
                                i16 full_result = (i8)bval * (i8)aval;
                                mem_write8_at(addr, (u8)(full_result & 0xFF));
                            } else {
                                u16 full_result = (u8)bval * (u8)aval;
                                mem_write8_at(addr, (u8)(full_result & 0xFF));
                            }
                        } else if (opcode == "DIV") {
                            if (aval == 0) {
                                OF = true;
                                ZF = true;
                                mem_write8_at(addr, 0);
                                cout << "WARNING: Division by zero at instruction, result set to 0\n";
                            } else {
                                OF = false;
                                if (sign == 'S') mem_write8_at(addr, (u8)((i8)bval / (i8)aval));
                                else mem_write8_at(addr, (u8)((u8)bval / (u8)aval));
                            }
                        }
                    } else {
                        throw runtime_error("B must be r8N or memory for 8-bit op: " + B);
                    }
                } else if (size == 'H') {
                    // 16-bit arithmetic
                    int aval = 0;
                    if (is_r16(A)) aval = (int)regs16[get_r16_index(A)];
                    else if (is_number(A)) aval = parse_int(A) & 0xFFFF;
                    else if (is_mem(A)) aval = mem_read16_at(resolve_address(A));
                    else throw runtime_error("unsupported A for 16-bit op: " + A);

                    if (is_r16(B)) {
                        int bi = get_r16_index(B);
                        int bval = regs16[bi];
                        int result;
                        
                        if (opcode == "ADD") {
                            result = bval + aval;
                            regs16[bi] = (u16)result;
                            set_flags_add(aval, bval, result, true);
                        } else if (opcode == "SUB") {
                            result = bval - aval;
                            regs16[bi] = (u16)result;
                            set_flags_sub(aval, bval, result, true);
                        } else if (opcode == "MUL") {
                            // 16x16 = 32-bit result: low in bi, high in bi+1
                            if (sign == 'S') {
                                i32 full_result = (i16)bval * (i16)aval;
                                regs16[bi] = (u16)(full_result & 0xFFFF);
                                if (bi + 1 < 32) regs16[bi + 1] = (u16)((full_result >> 16) & 0xFFFF);
                            } else {
                                u32 full_result = (u16)bval * (u16)aval;
                                regs16[bi] = (u16)(full_result & 0xFFFF);
                                if (bi + 1 < 32) regs16[bi + 1] = (u16)((full_result >> 16) & 0xFFFF);
                            }
                        } else if (opcode == "DIV") {
                            if (aval == 0) {
                                OF = true;
                                ZF = true;
                                regs16[bi] = 0;
                                cout << "WARNING: Division by zero at instruction, result set to 0\n";
                            } else {
                                OF = false;
                                if (sign == 'S') {
                                    regs16[bi] = (u16)((i16)bval / (i16)aval);
                                    // Store remainder in bi+1 if available
                                    if (bi + 1 < 32) regs16[bi + 1] = (u16)((i16)bval % (i16)aval);
                                } else {
                                    regs16[bi] = (u16)((u16)bval / (u16)aval);
                                    // Store remainder in bi+1 if available
                                    if (bi + 1 < 32) regs16[bi + 1] = (u16)((u16)bval % (u16)aval);
                                }
                            }
                        }
                    } else if (is_mem(B)) {
                        u32 addr = resolve_address(B);
                        u16 bval = mem_read16_at(addr);
                        int result;
                        
                        if (opcode == "ADD") {
                            result = bval + aval;
                            mem_write16_at(addr, (u16)result);
                            set_flags_add(aval, bval, result, true);
                        } else if (opcode == "SUB") {
                            result = bval - aval;
                            mem_write16_at(addr, (u16)result);
                            set_flags_sub(aval, bval, result, true);
                        } else if (opcode == "MUL") {
                            // For memory, store low word only (high word lost)
                            if (sign == 'S') {
                                i32 full_result = (i16)bval * (i16)aval;
                                mem_write16_at(addr, (u16)(full_result & 0xFFFF));
                            } else {
                                u32 full_result = (u16)bval * (u16)aval;
                                mem_write16_at(addr, (u16)(full_result & 0xFFFF));
                            }
                        } else if (opcode == "DIV") {
                            if (aval == 0) {
                                OF = true;
                                ZF = true;
                                mem_write16_at(addr, 0);
                                cout << "WARNING: Division by zero at instruction, result set to 0\n";
                            } else {
                                OF = false;
                                if (sign == 'S') mem_write16_at(addr, (u16)((i16)bval / (i16)aval));
                                else mem_write16_at(addr, (u16)((u16)bval / (u16)aval));
                            }
                        }
                    } else {
                        throw runtime_error("B must be r16N or memory for 16-bit op: " + B);
                    }
                } else {
                    throw runtime_error("unknown size prefix in opcode: " + op);
                }
                continue;
            }

            // ABS - Absolute Value
            // Syntax: ABS operand
            // Makes value positive (removes sign)
            if (op == "ABS") {
                if (toks.size() < 2) throw runtime_error("ABS needs 1 argument");
                string A = toks[1];

                if (is_r8(A)) {
                    int idx = get_r8_index(A);
                    i8 val = (i8)regs8[idx];
                    regs8[idx] = (u8)(val < 0 ? -val : val);
                } else if (is_r16(A)) {
                    int idx = get_r16_index(A);
                    i16 val = (i16)regs16[idx];
                    regs16[idx] = (u16)(val < 0 ? -val : val);
                } else if (is_mem(A)) {
                    u32 addr = resolve_address(A);
                    i8 val = (i8)mem_read8_at(addr);
                    mem_write8_at(addr, (u8)(val < 0 ? -val : val));
                } else throw runtime_error("ABS operand must be r8N, r16N, or [addr]");

                continue;
            }

            // CLR - Clear (set to zero)
            // Syntax: CLR operand
            // More efficient/readable than MOV 0 operand
            if (op == "CLR") {
                if (toks.size() < 2) throw runtime_error("CLR needs 1 argument");
                string A = toks[1];

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = 0;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = 0;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), 0);
                } else throw runtime_error("CLR operand must be r8N, r16N, or [addr]");

                continue;
            }

            // SETZ - Set if Zero
            // Syntax: SETZ operand
            // Sets operand to 1 if ZF=1, else 0
            if (op == "SETZ" || op == "SETE") {
                if (toks.size() < 2) throw runtime_error("SETZ needs 1 argument");
                string A = toks[1];
                u8 val = ZF ? 1 : 0;

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = val;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = val;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), val);
                } else throw runtime_error("SETZ operand must be r8N, r16N, or [addr]");

                continue;
            }

            // SETNZ - Set if Not Zero
            // Syntax: SETNZ operand
            // Sets operand to 1 if ZF=0, else 0
            if (op == "SETNZ" || op == "SETNE") {
                if (toks.size() < 2) throw runtime_error("SETNZ needs 1 argument");
                string A = toks[1];
                u8 val = !ZF ? 1 : 0;

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = val;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = val;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), val);
                } else throw runtime_error("SETNZ operand must be r8N, r16N, or [addr]");

                continue;
            }

            // SETC - Set if Carry
            // Syntax: SETC operand
            // Sets operand to 1 if CF=1, else 0
            if (op == "SETC") {
                if (toks.size() < 2) throw runtime_error("SETC needs 1 argument");
                string A = toks[1];
                u8 val = CF ? 1 : 0;

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = val;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = val;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), val);
                } else throw runtime_error("SETC operand must be r8N, r16N, or [addr]");

                continue;
            }

            // SETNC - Set if Not Carry
            // Syntax: SETNC operand
            // Sets operand to 1 if CF=0, else 0
            if (op == "SETNC") {
                if (toks.size() < 2) throw runtime_error("SETNC needs 1 argument");
                string A = toks[1];
                u8 val = !CF ? 1 : 0;

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = val;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = val;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), val);
                } else throw runtime_error("SETNC operand must be r8N, r16N, or [addr]");

                continue;
            }

            // SETS - Set if Sign (negative)
            // Syntax: SETS operand
            // Sets operand to 1 if SF=1, else 0
            if (op == "SETS") {
                if (toks.size() < 2) throw runtime_error("SETS needs 1 argument");
                string A = toks[1];
                u8 val = SF ? 1 : 0;

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = val;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = val;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), val);
                } else throw runtime_error("SETS operand must be r8N, r16N, or [addr]");

                continue;
            }

            // SETNS - Set if Not Sign (positive)
            // Syntax: SETNS operand
            // Sets operand to 1 if SF=0, else 0
            if (op == "SETNS") {
                if (toks.size() < 2) throw runtime_error("SETNS needs 1 argument");
                string A = toks[1];
                u8 val = !SF ? 1 : 0;

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = val;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = val;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), val);
                } else throw runtime_error("SETNS operand must be r8N, r16N, or [addr]");

                continue;
            }

            // SETL - Set if Less (SF=1)
            // Syntax: SETL operand
            // Sets operand to 1 if last comparison was less than
            if (op == "SETL") {
                if (toks.size() < 2) throw runtime_error("SETL needs 1 argument");
                string A = toks[1];
                u8 val = SF ? 1 : 0;

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = val;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = val;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), val);
                } else throw runtime_error("SETL operand must be r8N, r16N, or [addr]");

                continue;
            }

            // SETG - Set if Greater (SF=0 and ZF=0)
            // Syntax: SETG operand
            // Sets operand to 1 if last comparison was greater than
            if (op == "SETG") {
                if (toks.size() < 2) throw runtime_error("SETG needs 1 argument");
                string A = toks[1];
                u8 val = (!SF && !ZF) ? 1 : 0;

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = val;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = val;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), val);
                } else throw runtime_error("SETG operand must be r8N, r16N, or [addr]");

                continue;
            }

            // SETLE - Set if Less or Equal (SF=1 or ZF=1)
            // Syntax: SETLE operand
            if (op == "SETLE") {
                if (toks.size() < 2) throw runtime_error("SETLE needs 1 argument");
                string A = toks[1];
                u8 val = (SF || ZF) ? 1 : 0;

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = val;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = val;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), val);
                } else throw runtime_error("SETLE operand must be r8N, r16N, or [addr]");

                continue;
            }

            // SETGE - Set if Greater or Equal (SF=0)
            // Syntax: SETGE operand
            if (op == "SETGE") {
                if (toks.size() < 2) throw runtime_error("SETGE needs 1 argument");
                string A = toks[1];
                u8 val = !SF ? 1 : 0;

                if (is_r8(A)) {
                    regs8[get_r8_index(A)] = val;
                } else if (is_r16(A)) {
                    regs16[get_r16_index(A)] = val;
                } else if (is_mem(A)) {
                    mem_write8_at(resolve_address(A), val);
                } else throw runtime_error("SETGE operand must be r8N, r16N, or [addr]");

                continue;
            }

            // ROL - Rotate Left
            if (op == "ROL") {
                if (toks.size() < 3) throw runtime_error("ROL needs 2 arguments");
                string count_str = toks[1], operand = toks[2];
    
                int count = 0;
                if (is_r8(count_str)) count = regs8[get_r8_index(count_str)];
                else if (is_number(count_str)) count = parse_int(count_str);
                else throw runtime_error("ROL count must be register or immediate");
    
                if (is_r8(operand)) {
                    int idx = get_r8_index(operand);
                    u8 val = regs8[idx];
                    count = count % 8;
                    if (count > 0) {  // ← ADD THIS CHECK
                        regs8[idx] = (val << count) | (val >> (8 - count));
                        CF = ((val >> (8 - count)) & 1) != 0;
                    }
                } else if (is_r16(operand)) {
                    int idx = get_r16_index(operand);
                    u16 val = regs16[idx];
                    count = count % 16;
                    if (count > 0) {  // ← ADD THIS CHECK
                        regs16[idx] = (val << count) | (val >> (16 - count));
                        CF = ((val >> (16 - count)) & 1) != 0;
                    }
                } else if (is_mem(operand)) {
                    u32 addr = resolve_address(operand);
                    u8 val = mem_read8_at(addr);
                    count = count % 8;
                    if (count > 0) {  // ← ADD THIS CHECK
                        mem_write8_at(addr, (val << count) | (val >> (8 - count)));
                        CF = ((val >> (8 - count)) & 1) != 0;
                    }
                } else {
                    throw runtime_error("ROL operand must be register or memory");
                }
                continue;
            }

            // ROR - Rotate Right
            if (op == "ROR") {
                if (toks.size() < 3) throw runtime_error("ROR needs 2 arguments");
                string count_str = toks[1], operand = toks[2];
                
                int count = 0;
                if (is_r8(count_str)) count = regs8[get_r8_index(count_str)];
                else if (is_number(count_str)) count = parse_int(count_str);
                else throw runtime_error("ROR count must be register or immediate");
                
                if (is_r8(operand)) {
                    int idx = get_r8_index(operand);
                    u8 val = regs8[idx];
                    count = count % 8;
                    if (count > 0) {  // ← ADD THIS CHECK
                        regs8[idx] = (val >> count) | (val << (8 - count));
                        CF = ((val >> (count - 1)) & 1) != 0;
                    }
                } else if (is_r16(operand)) {
                    int idx = get_r16_index(operand);
                    u16 val = regs16[idx];
                    count = count % 16;
                    if (count > 0) {  // ← ADD THIS CHECK
                        regs16[idx] = (val >> count) | (val << (16 - count));
                        CF = ((val >> (count - 1)) & 1) != 0;
                    }
                } else if (is_mem(operand)) {
                    u32 addr = resolve_address(operand);
                    u8 val = mem_read8_at(addr);
                    count = count % 8;
                    if (count > 0) {  // ← ADD THIS CHECK
                        mem_write8_at(addr, (val >> count) | (val << (8 - count)));
                        CF = ((val >> (count - 1)) & 1) != 0;
                    }
                } else {
                    throw runtime_error("ROR operand must be register or memory");
                }
                continue;
            }

            // TEST - Bitwise AND that only sets flags (doesn't store result)
            // Syntax: TEST operand1 operand2
            // Commonly used to check if bits are set
            if (op == "TEST") {
                if (toks.size() < 3) throw runtime_error("TEST needs 2 arguments");
                string A = toks[1], B = toks[2];
    
                int aval = 0, bval = 0;
                bool is_16bit = false;
    
                // Parse operand A
                if (is_r8(A)) {
                    aval = regs8[get_r8_index(A)];
                } else if (is_r16(A)) {
                    aval = regs16[get_r16_index(A)];
                    is_16bit = true;
                } else if (is_mem(A)) {
                    aval = mem_read8_at(resolve_address(A));
                } else if (is_number(A)) {
                    aval = parse_int(A);
                } else {
                    throw runtime_error("TEST: unsupported first operand: " + A);
                }
                
                // Parse operand B
                if (is_r8(B)) {
                    bval = regs8[get_r8_index(B)];
                } else if (is_r16(B)) {
                    bval = regs16[get_r16_index(B)];
                    is_16bit = true;
                } else if (is_mem(B)) {
                    bval = mem_read8_at(resolve_address(B));
                } else if (is_number(B)) {
                    bval = parse_int(B);
                } else {
                    throw runtime_error("TEST: unsupported second operand: " + B);
                }
                
                // Perform AND and set flags (but don't store result)
                int result = aval & bval;
                
                if (is_16bit) {
                    ZF = ((result & 0xFFFF) == 0);
                    SF = ((result & 0x8000) != 0);
                } else {
                    ZF = ((result & 0xFF) == 0);
                    SF = ((result & 0x80) != 0);
                }
                
                // TEST always clears CF and OF
                CF = false;
                OF = false;
                
                continue;
            }

            // Bitwise ops: LAND, LOR, LXOR, LNOT, LSHL, LSHR, HAND, etc.
            if ((op.size() >= 3) && 
                (op.find("AND") != string::npos || op.find("OR") != string::npos ||
                 op.find("XOR") != string::npos || op.find("NOT") != string::npos ||
                 op.find("SHL") != string::npos || op.find("SHR") != string::npos)) {
                
                char size = op[0];
                string opcode;
                
                if (op.find("AND") != string::npos) opcode = "AND";
                else if (op.find("OR") != string::npos) opcode = "OR";
                else if (op.find("XOR") != string::npos) opcode = "XOR";
                else if (op.find("NOT") != string::npos) opcode = "NOT";
                else if (op.find("SHL") != string::npos) opcode = "SHL";
                else if (op.find("SHR") != string::npos) opcode = "SHR";

                if (toks.size() < 2) throw runtime_error(op + " needs at least 1 argument");
                string A = toks[1], B = (toks.size() >= 3 ? toks[2] : "");

                if (size == 'L') {
                    int aval = 0;
                    if (is_r8(A)) aval = regs8[get_r8_index(A)];
                    else if (is_number(A)) aval = parse_int(A) & 0xFF;
                    else if (is_mem(A)) aval = mem_read8_at(resolve_address(A));
                    else if (opcode != "NOT") throw runtime_error("unsupported A for L-bit op: " + A);
                    
                    if (opcode != "NOT") {
                        if (is_r8(B)) {
                            int bi = get_r8_index(B);
                            int bval = regs8[bi];
                            if (opcode == "AND") regs8[bi] = (u8)(bval & aval);
                            else if (opcode == "OR") regs8[bi] = (u8)(bval | aval);
                            else if (opcode == "XOR") regs8[bi] = (u8)(bval ^ aval);
                            else if (opcode == "SHL") regs8[bi] = (u8)(bval << aval);
                            else if (opcode == "SHR") regs8[bi] = (u8)(bval >> aval);
                        } else if (is_mem(B)) {
                            u32 addr = resolve_address(B);
                            u8 bval = mem_read8_at(addr);
                            if (opcode == "AND") mem_write8_at(addr, (u8)(bval & aval));
                            else if (opcode == "OR") mem_write8_at(addr, (u8)(bval | aval));
                            else if (opcode == "XOR") mem_write8_at(addr, (u8)(bval ^ aval));
                            else if (opcode == "SHL") mem_write8_at(addr, (u8)(bval << aval));
                            else if (opcode == "SHR") mem_write8_at(addr, (u8)(bval >> aval));
                        } else throw runtime_error("B must be r8N or memory for L-bit bitwise op");
                    } else {
                        if (is_r8(A)) {
                            int ai = get_r8_index(A);
                            regs8[ai] = ~regs8[ai];
                        } else if (is_mem(A)) {
                            u32 addr = resolve_address(A);
                            mem_write8_at(addr, ~mem_read8_at(addr));
                        } else throw runtime_error("unsupported operand for L-bit NOT");
                    }
                } else if (size == 'H') {
                    int aval = 0;
                    if (is_r16(A)) aval = regs16[get_r16_index(A)];
                    else if (is_number(A)) aval = parse_int(A) & 0xFFFF;
                    else if (is_mem(A)) aval = mem_read16_at(resolve_address(A));
                    else if (opcode != "NOT") throw runtime_error("unsupported A for H-bit op: " + A);
                    
                    if (opcode != "NOT") {
                        if (is_r16(B)) {
                            int bi = get_r16_index(B);
                            int bval = regs16[bi];
                            if (opcode == "AND") regs16[bi] = (u16)(bval & aval);
                            else if (opcode == "OR") regs16[bi] = (u16)(bval | aval);
                            else if (opcode == "XOR") regs16[bi] = (u16)(bval ^ aval);
                            else if (opcode == "SHL") regs16[bi] = (u16)(bval << aval);
                            else if (opcode == "SHR") regs16[bi] = (u16)(bval >> aval);
                        } else if (is_mem(B)) {
                            u32 addr = resolve_address(B);
                            u16 bval = mem_read16_at(addr);
                            if (opcode == "AND") mem_write16_at(addr, (u16)(bval & aval));
                            else if (opcode == "OR") mem_write16_at(addr, (u16)(bval | aval));
                            else if (opcode == "XOR") mem_write16_at(addr, (u16)(bval ^ aval));
                            else if (opcode == "SHL") mem_write16_at(addr, (u16)(bval << aval));
                            else if (opcode == "SHR") mem_write16_at(addr, (u16)(bval >> aval));
                        } else throw runtime_error("B must be r16N or memory for H-bit bitwise op");
                    } else {
                        if (is_r16(A)) {
                            int ai = get_r16_index(A);
                            regs16[ai] = ~regs16[ai];
                        } else if (is_mem(A)) {
                            u32 addr = resolve_address(A);
                            mem_write16_at(addr, ~mem_read16_at(addr));
                        } else throw runtime_error("unsupported operand for H-bit NOT");
                    }
                } else throw runtime_error("unknown size prefix in bitwise opcode: " + op);

                continue;
            }

            // Memory ops
            if (op == "LWSB" || op == "HWSB") {
                if (toks.size() < 3) throw runtime_error("LWSB/HWSB needs 2 args");
                string A = toks[1], B = toks[2];
                int aval = 0;
                
                if (is_r8(A)) aval = regs8[get_r8_index(A)];
                else if (is_number(A)) aval = parse_int(A) & 0xFF;
                else throw runtime_error("unsupported A for WSB: " + A);
                
                u32 addr;
                if (is_mem(B)) addr = resolve_address(B);
                else if (is_number(B)) addr = parse_int(B);
                else throw runtime_error("unsupported B address token: " + B);
                
                if (op == "LWSB") {
                    if (addr < ram8_offset || addr >= ram8_offset + ram8_size) {
                        throw runtime_error("LWSB 8-bit addressing allowed only within 8-bit RAM region");
                    }
                }
                mem_write8_at(addr, (u8)aval);
                continue;
            }

            if (op == "HWSW") {
                if (toks.size() < 3) throw runtime_error("HWSW needs 2 args");
                string A = toks[1], B = toks[2];
                int aval = 0;
                
                if (is_r16(A)) aval = regs16[get_r16_index(A)];
                else if (is_number(A)) aval = parse_int(A) & 0xFFFF;
                else throw runtime_error("unsupported A for HWSW: " + A);
                
                u32 addr;
                if (is_mem(B)) addr = resolve_address(B);
                else if (is_number(B)) addr = parse_int(B);
                else throw runtime_error("unsupported B for HWSW: " + B);
                
                mem_write16_at(addr, (u16)aval);
                continue;
            }

            if (op == "LPUT") {
                if (toks.size() < 3) throw runtime_error("LPUT needs 2 args");
                string A = toks[1], B = toks[2];
                int aval = 0;
                
                if (is_number(A)) aval = parse_int(A) & 0xFF;
                else if (is_r8(A)) aval = regs8[get_r8_index(A)];
                else throw runtime_error("unsupported A for LPUT: " + A);
                
                if (!is_r8(B)) throw runtime_error("LPUT B must be r8N");
                int bi = get_r8_index(B);
                regs8[bi] = (u8)aval;
                continue;
            }

            if (op == "HPUT") {
                if (toks.size() < 3) throw runtime_error("HPUT needs 2 args");
                string A = toks[1], B = toks[2];
                int aval = 0;
                
                if (is_number(A)) aval = parse_int(A) & 0xFFFF;
                else if (is_r16(A)) aval = regs16[get_r16_index(A)];
                else throw runtime_error("unsupported A for HPUT: " + A);
                
                if (!is_r16(B)) throw runtime_error("HPUT B must be r16N");
                int bi = get_r16_index(B);
                regs16[bi] = (u16)aval;
                continue;
            }

            if (op == "LREAD" || op == "HREAD") {
                if (toks.size() < 3) throw runtime_error("LREAD/HREAD needs 2 args");
                string A = toks[1], B = toks[2];
                u32 addr;
                
                if (is_mem(A)) addr = resolve_address(A);
                else if (is_number(A)) addr = parse_int(A);
                else throw runtime_error("unsupported A for READ: " + A);
                
                if (op == "LREAD") {
                    if (addr < ram8_offset || addr >= ram8_offset + ram8_size) {
                        throw runtime_error("LREAD address must be within 8-bit RAM region");
                    }
                    u8 val = mem_read8_at(addr);
                    if (!is_r8(B)) throw runtime_error("LREAD target must be r8N");
                    int bi = get_r8_index(B);
                    regs8[bi] = val;
                } else {  // HREAD
                    u16 val = mem_read16_at(addr);  // Changed to read 16 bits
                    if (!is_r16(B)) throw runtime_error("HREAD target must be r16N");  // Changed to r16
                    int bi = get_r16_index(B);  // Changed to get r16 index
                    regs16[bi] = val;  // Changed to write to r16
                }
                continue;
            }

            if (op == "DUMP") {
                if (toks.size() == 1 || toks[1] == "REGS") {
                    cout << "r8: ";
                    for (int i = 0; i < 8; i++) {
                        cout << "r8_" << i << '=' << (int)regs8[i] << " ";
                    }
                    cout << "\nr16: ";
                    for (int i = 0; i < 8; i++) {
                        cout << "r16_" << i << '=' << (int)regs16[i] << " ";
                    }
                    cout << "\n";
                } else if (toks[1] == "MEM") {
                    int start = 0, len = 64;
                    if (toks.size() >= 4) { 
                        start = parse_int(toks[2]); 
                        len = parse_int(toks[3]); 
                    }
                    for (int i = 0; i < len; i++) {
                        if (i % 16 == 0) cout << hex << setw(4) << setfill('0') << (start + i) << ": ";
                        cout << hex << setw(2) << setfill('0') << (int)mem_read8_at(start + i) << " ";
                        if (i % 16 == 15) cout << "\n";
                    }
                    cout << dec << "\n";
                }
                continue;
            }

            // LSAR - Logical Shift Arithmetic Right (8-bit, preserves sign)
            // Syntax: LSAR count operand
            if (op == "LSAR") {
                if (toks.size() < 3) throw runtime_error("LSAR needs 2 arguments");
                string count_str = toks[1], operand = toks[2];
                
                int count = 0;
                if (is_r8(count_str)) count = regs8[get_r8_index(count_str)];
                else if (is_number(count_str)) count = parse_int(count_str);
                else throw runtime_error("LSAR count must be register or immediate");
                
                if (is_r8(operand)) {
                    int idx = get_r8_index(operand);
                    i8 val = (i8)regs8[idx];  // Treat as signed
                    regs8[idx] = (u8)(val >> count);  // Arithmetic shift
                } else if (is_mem(operand)) {
                    u32 addr = resolve_address(operand);
                    i8 val = (i8)mem_read8_at(addr);
                    mem_write8_at(addr, (u8)(val >> count));
                } else {
                    throw runtime_error("LSAR operand must be r8 or memory");
                }
                continue;
            }

            // HSAR - High Shift Arithmetic Right (16-bit, preserves sign)
            // Syntax: HSAR count operand
            if (op == "HSAR") {
                if (toks.size() < 3) throw runtime_error("HSAR needs 2 arguments");
                string count_str = toks[1], operand = toks[2];
                
                int count = 0;
                if (is_r8(count_str)) count = regs8[get_r8_index(count_str)];
                else if (is_number(count_str)) count = parse_int(count_str);
                else throw runtime_error("HSAR count must be register or immediate");
                
                if (is_r16(operand)) {
                    int idx = get_r16_index(operand);
                    i16 val = (i16)regs16[idx];  // Treat as signed
                    regs16[idx] = (u16)(val >> count);  // Arithmetic shift
                } else if (is_mem(operand)) {
                    u32 addr = resolve_address(operand);
                    i16 val = (i16)mem_read16_at(addr);
                    mem_write16_at(addr, (u16)(val >> count));
                } else {
                    throw runtime_error("HSAR operand must be r16 or memory");
                }
                continue;
            }

            if (op == "LEA") {
                if (toks.size() < 3) throw runtime_error("LEA needs 2 arguments");
                string addr_expr = toks[1], dst = toks[2];
    
                if (!is_mem(addr_expr)) throw runtime_error("LEA first arg must be [address expression]");
    
                // Parse the address expression
                string inside = addr_expr.substr(1, addr_expr.size() - 2);
                inside = trim(inside);
    
                u32 effective_addr = 0;
    
                // Check for addition: [base+offset]
                size_t plus_pos = inside.find('+');
                if (plus_pos != string::npos) {
                    string base_str = trim(inside.substr(0, plus_pos));
                    string offset_str = trim(inside.substr(plus_pos + 1));
        
                    int base = 0, offset = 0;
        
                    // Parse base
                    if (is_r8(base_str)) base = regs8[get_r8_index(base_str)];
                    else if (is_r16(base_str)) base = regs16[get_r16_index(base_str)];
                    else if (is_number(base_str)) base = parse_int(base_str);
                    else throw runtime_error("LEA: unsupported base: " + base_str);
        
                    // Parse offset
                    if (is_r8(offset_str)) offset = regs8[get_r8_index(offset_str)];
                    else if (is_r16(offset_str)) offset = regs16[get_r16_index(offset_str)];
                    else if (is_number(offset_str)) offset = parse_int(offset_str);
                    else throw runtime_error("LEA: unsupported offset: " + offset_str);
        
                    effective_addr = base + offset;
                } else {
                    // Simple address without addition
                    if (is_r8(inside)) effective_addr = regs8[get_r8_index(inside)];
                    else if (is_r16(inside)) effective_addr = regs16[get_r16_index(inside)];
                    else if (is_number(inside)) effective_addr = parse_int(inside);
                    else throw runtime_error("LEA: unsupported address: " + inside);
                }
    
                // Store effective address in destination register
                if (is_r8(dst)) {
                    regs8[get_r8_index(dst)] = (u8)effective_addr;
                } else if (is_r16(dst)) {
                    regs16[get_r16_index(dst)] = (u16)effective_addr;
                } else {
                    throw runtime_error("LEA destination must be register");
                }
                continue;
            }

            if (op == "LCMP" || op == "HCMP") {
                if (toks.size() < 3) throw runtime_error("CMP needs 2 args");
                string A = toks[1], B = toks[2];
                int aval = 0, bval = 0;

                if (op[0] == 'L') {
                    if (is_r8(A)) aval = regs8[get_r8_index(A)];
                    else if (is_number(A)) aval = parse_int(A) & 0xFF;
                    else throw runtime_error("unsupported A for LCMP");
                    
                    if (is_r8(B)) bval = regs8[get_r8_index(B)];
                    else if (is_mem(B)) bval = mem_read8_at(resolve_address(B));
                    else if (is_number(B)) bval = parse_int(B) & 0xFF;
                    else throw runtime_error("unsupported B for LCMP");
                } else {
                    if (is_r16(A)) aval = regs16[get_r16_index(A)];
                    else if (is_number(A)) aval = parse_int(A) & 0xFFFF;
                    else throw runtime_error("unsupported A for HCMP");
                    
                    if (is_r16(B)) bval = regs16[get_r16_index(B)];
                    else if (is_mem(B)) bval = mem_read16_at(resolve_address(B));
                    else if (is_number(B)) bval = parse_int(B) & 0xFFFF;
                    else throw runtime_error("unsupported B for HCMP");
                }
                set_flags(aval, bval);
                continue;
            }

            if (op == "INC" || op == "DEC") {
                if (toks.size() < 2) throw runtime_error(op + " needs 1 argument");
                string A = toks[1];

                if (is_r8(A)) {
                    int idx = get_r8_index(A);
                    u8 result;
                    if (op == "INC") {
                        result = (u8)(regs8[idx] + 1);
                        regs8[idx] = result;
                    } else {
                        result = (u8)(regs8[idx] - 1);
                        regs8[idx] = result;
                    }
                    // Set flags
                    ZF = (result == 0);
                    SF = ((result & 0x80) != 0);
                } else if (is_r16(A)) {
                    int idx = get_r16_index(A);
                    u16 result;
                    if (op == "INC") {
                        result = (u16)(regs16[idx] + 1);
                        regs16[idx] = result;
                    } else {
                        result = (u16)(regs16[idx] - 1);
                        regs16[idx] = result;
                    }
                    // Set flags
                    ZF = (result == 0);
                    SF = ((result & 0x8000) != 0);
                } else if (is_mem(A)) {
                    u32 addr = resolve_address(A);
                    u8 val = mem_read8_at(addr);
                    u8 result;
                    if (op == "INC") {
                        result = val + 1;
                        mem_write8_at(addr, result);
                    } else {
                        result = val - 1;
                        mem_write8_at(addr, result);
                    }
                    // Set flags
                    ZF = (result == 0);
                    SF = ((result & 0x80) != 0);
                } else throw runtime_error(op + " operand must be r8N, r16N, or [addr]");

                continue;
            }

            if (op == "NEG") {
                if (toks.size() < 2) throw runtime_error("NEG needs 1 argument");
                string A = trim(toks[1]);

                if (is_r8(A)) {
                    int idx = get_r8_index(A);
                    regs8[idx] = (u8)(-(i8)regs8[idx]);
                } else if (is_r16(A)) {
                    int idx = get_r16_index(A);
                    regs16[idx] = (u16)(-(i16)regs16[idx]);
                } else if (is_mem(A)) {
                    u32 addr = resolve_address(A);
                    u8 val = mem_read8_at(addr);
                    mem_write8_at(addr, (u8)(-(i8)val));
                } else throw runtime_error("NEG operand must be r8N, r16N, or [addr]");

                continue;
            }

            if (op == "DREAD") {
                if (toks.size() < 3) throw runtime_error("DREAD needs 2 arguments: sector and r8 target");
                u16 sector = parse_int(toks[1]);
                if (!is_r8(toks[2])) throw runtime_error("DREAD target must be r8N");
                u8 r = get_r8_index(toks[2]);

                if (!disk_fp && OPEN_DISK(DISK_FILE) != 0)
                    throw runtime_error("DREAD failed: cannot open disk");

                uint8_t buf[512];
                if (READ_DISK(sector, buf) != 0)
                    throw runtime_error("DREAD failed");

                regs8[r] = buf[0];
                continue;
            }

            if (op == "DWRITE") {
                if (toks.size() < 3) throw runtime_error("DWRITE needs 2 arguments: sector and r8 source");
                u16 sector = parse_int(toks[1]);
                if (!is_r8(toks[2])) throw runtime_error("DWRITE source must be r8N");
                u8 r = get_r8_index(toks[2]);

                if (!disk_fp && OPEN_DISK(DISK_FILE) != 0)
                    throw runtime_error("DWRITE failed: cannot open disk");

                uint8_t buf[512] = {0};
                buf[0] = regs8[r];
                if (WRITE_DISK(sector, buf) != 0)
                    throw runtime_error("DWRITE failed");
                continue;
            }

            if (op == "JMP") {
                if (toks.size() < 2) throw runtime_error("JMP needs a label");
                string lbl = toks[1];
                if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                pc = labels[lbl];
                continue;
            }

            if (op == "JE" || op == "JZ") {
                if (toks.size() < 2) throw runtime_error("JE/JZ needs a label");
                if (ZF) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }

            if (op == "JNE" || op == "JNZ") {
                if (toks.size() < 2) throw runtime_error("JNE/JNZ needs a label");
                if (!ZF) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }

            if (op == "JL") {
                if (toks.size() < 2) throw runtime_error("JL needs a label");
                if (SF) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }

            if (op == "JLE") {
                if (toks.size() < 2) throw runtime_error("JLE needs a label");
                if (SF || ZF) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }

            if (op == "JG") {
                if (toks.size() < 2) throw runtime_error("JG needs a label");
                if (!SF && !ZF) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }

            if (op == "JGE") {
                if (toks.size() < 2) throw runtime_error("JGE needs a label");
                if (!SF) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }

            if (op == "JC") {  // Jump if Carry
                if (toks.size() < 2) throw runtime_error("JC needs a label");
                if (CF) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }

            if (op == "JNC") {  // Jump if Not Carry
                if (toks.size() < 2) throw runtime_error("JNC needs a label");
                if (!CF) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }

            if (op == "JO") {  // Jump if Overflow
                if (toks.size() < 2) throw runtime_error("JO needs a label");
                if (OF) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }

            if (op == "JNO") {  // Jump if Not Overflow
                if (toks.size() < 2) throw runtime_error("JNO needs a label");
                if (!OF) {
                    string lbl = toks[1];
                    if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
                    pc = labels[lbl];
                }
                continue;
            }

            // MOV - Move data between registers/memory
            if (op == "MOV") {
                if (toks.size() < 3) throw runtime_error("MOV needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                // Determine source value
                int val = 0;
                bool is16_src = false;
                
                if (is_r8(src)) {
                    val = regs8[get_r8_index(src)];
                } else if (is_r16(src)) {
                    val = regs16[get_r16_index(src)];
                    is16_src = true;
                } else if (is_mem(src)) {
                    u32 addr = resolve_address(src);
                    // Check if destination is 16-bit to determine read size
                    if (is_r16(dst)) {
                        val = mem_read16_at(addr);
                        is16_src = true;
                    } else {
                        val = mem_read8_at(addr);
                    }
                } else if (is_number(src)) {
                    val = parse_int(src);
                } else {
                    throw runtime_error("unsupported MOV source: " + src);
                }
                
                // Write to destination
                if (is_r8(dst)) {
                    regs8[get_r8_index(dst)] = (u8)val;
                } else if (is_r16(dst)) {
                    regs16[get_r16_index(dst)] = (u16)val;
                } else if (is_mem(dst)) {
                    u32 addr = resolve_address(dst);
                    if (is16_src) mem_write16_at(addr, (u16)val);
                    else mem_write8_at(addr, (u8)val);
                } else {
                    throw runtime_error("unsupported MOV destination: " + dst);
                }
                continue;
            }

            // LOADI - Load immediate value (cleaner syntax than LPUT/HPUT)
            if (op == "LOADI") {
                if (toks.size() < 3) throw runtime_error("LOADI needs 2 arguments");
                string val_str = toks[1], dst = toks[2];
                
                if (!is_number(val_str)) throw runtime_error("LOADI first arg must be immediate value");
                int val = parse_int(val_str);
                
                if (is_r8(dst)) {
                    regs8[get_r8_index(dst)] = (u8)val;
                } else if (is_r16(dst)) {
                    regs16[get_r16_index(dst)] = (u16)val;
                } else {
                    throw runtime_error("LOADI destination must be register");
                }
                continue;
            }

            // SALC - Set AL (r8_0) from Carry Flag
            // x86 undocumented instruction: AL = CF ? 0xFF : 0x00
            if (op == "SALC") {
                regs8[0] = CF ? 0xFF : 0x00;
                continue;
            }

            // STC - Set Carry Flag
            if (op == "STC") {
                CF = true;
                continue;
            }

            // CLC - Clear Carry Flag
            if (op == "CLC") {
                CF = false;
                continue;
            }

            // CMC - Complement Carry Flag
            if (op == "CMC") {
                CF = !CF;
                continue;
            }

            if (op == "PRINT") {
                if (toks.size() < 2) throw runtime_error("PRINT needs 1 argument");
                string arg = toks[1];

                if (is_r8(arg)) {
                    int idx = get_r8_index(arg);
                    cout << arg << " = " << (int)regs8[idx] << "\n";
                } else if (is_r16(arg)) {
                    int idx = get_r16_index(arg);
                    cout << arg << " = " << regs16[idx] << "\n";
                } else if (is_mem(arg)) {
                    u32 addr = resolve_address(arg);
                    cout << arg << " = " << (int)mem_read8_at(addr) << "\n";
                } else if (is_number(arg)) {
                    cout << arg << " = " << parse_int(arg) << "\n";
                } else if (arg.size() >= 2 && arg.front() == '"' && arg.back() == '"') {
                    string str = arg.substr(1, arg.size() - 2);
                    // Process escape sequences
                    string processed;
                    for (size_t i = 0; i < str.size(); i++) {
                        if (str[i] == '\\' && i + 1 < str.size()) {
                            switch (str[i + 1]) {
                                case 'n': processed += '\n'; i++; break;
                                case 't': processed += '\t'; i++; break;
                                case 'r': processed += '\r'; i++; break;
                                case '\\': processed += '\\'; i++; break;
                                case '"': processed += '"'; i++; break;
                                default: processed += str[i]; break;
                            }
                        } else {
                            processed += str[i];
                        }
                    }
                    cout << processed << "\n";
                } else {
                    throw runtime_error("unsupported PRINT argument: " + arg);
                }

                continue;
            }

            if (op == "PRINTC") {
                if (toks.size() < 2) throw runtime_error("PRINTC needs 1 argument");
                string arg = toks[1];
                u8 value = 0;

                if (is_r8(arg)) value = regs8[get_r8_index(arg)];
                else if (is_number(arg)) value = (u8)parse_int(arg);
                else if (is_mem(arg)) value = mem_read8_at(resolve_address(arg));
                else throw runtime_error("unsupported PRINTC argument: " + arg);

                cout << (char)value;
                continue;
            }

            if (op == "PUSH") {
                if (toks.size() < 2) throw runtime_error("PUSH needs 1 argument");
                string A = toks[1];
                int val = 0;
                bool is16 = false;

                if (is_r8(A)) val = regs8[get_r8_index(A)];
                else if (is_r16(A)) { val = regs16[get_r16_index(A)]; is16 = true; }
                else if (is_number(A)) val = parse_int(A);
                else throw runtime_error("unsupported PUSH operand: " + A);

                if (is16) {
                    if (SP < stack_base + 2) throw runtime_error("stack overflow");
                    SP -= 2;
                    mem_write16_at(SP, (u16)val);
                } else {
                    if (SP <= stack_base) throw runtime_error("stack overflow");
                    SP -= 1;
                    mem_write8_at(SP, (u8)val);
                }
                continue;
            }

            if (op == "XCHG") {
                if (toks.size() < 3) throw runtime_error("XCHG needs 2 arguments");
                string A = toks[1], B = toks[2];
    
                // reg8 <-> reg8
                if (is_r8(A) && is_r8(B)) {
                    int ai = get_r8_index(A);
                    int bi = get_r8_index(B);
                    u8 temp = regs8[ai];
                    regs8[ai] = regs8[bi];
                    regs8[bi] = temp;
                }
                // reg16 <-> reg16
                else if (is_r16(A) && is_r16(B)) {
                    int ai = get_r16_index(A);
                    int bi = get_r16_index(B);
                    u16 temp = regs16[ai];
                    regs16[ai] = regs16[bi];
                    regs16[bi] = temp;
                }
                // reg8 <-> mem
                else if (is_r8(A) && is_mem(B)) {
                    int ai = get_r8_index(A);
                    u32 addr = resolve_address(B);
                    u8 temp = regs8[ai];
                    regs8[ai] = mem_read8_at(addr);
                    mem_write8_at(addr, temp);
                }
                // mem <-> reg8
                else if (is_mem(A) && is_r8(B)) {
                    u32 addr = resolve_address(A);
                    int bi = get_r8_index(B);
                    u8 temp = mem_read8_at(addr);
                    mem_write8_at(addr, regs8[bi]);
                    regs8[bi] = temp;
                }
                // reg16 <-> mem
                else if (is_r16(A) && is_mem(B)) {
                    int ai = get_r16_index(A);
                    u32 addr = resolve_address(B);
                    u16 temp = regs16[ai];
                    regs16[ai] = mem_read16_at(addr);
                    mem_write16_at(addr, temp);
                }
                // mem <-> reg16
                else if (is_mem(A) && is_r16(B)) {
                    u32 addr = resolve_address(A);
                    int bi = get_r16_index(B);
                    u16 temp = mem_read16_at(addr);
                    mem_write16_at(addr, regs16[bi]);
                    regs16[bi] = temp;
                }
                else {
                    throw runtime_error("XCHG: unsupported operand combination");
                }
                continue;
            }

            // CMPXCHG - Compare and Exchange (atomic)
            // Syntax: CMPXCHG expected new_value destination
            // If destination == expected, then destination = new_value and ZF=1
            // Else ZF=0 (operation failed)
            if (op == "CMPXCHG") {
                if (toks.size() < 4) throw runtime_error("CMPXCHG needs 3 arguments");
                string expected_str = toks[1], new_str = toks[2], dst = toks[3];
                
                int expected = 0, new_val = 0;
                bool is_16bit = false;
                
                // Parse expected value
                if (is_r8(expected_str)) {
                    expected = regs8[get_r8_index(expected_str)];
                } else if (is_r16(expected_str)) {
                    expected = regs16[get_r16_index(expected_str)];
                    is_16bit = true;
                } else if (is_number(expected_str)) {
                    expected = parse_int(expected_str);
                } else {
                    throw runtime_error("CMPXCHG expected must be register or immediate");
                }
                
                // Parse new value
                if (is_r8(new_str)) {
                    new_val = regs8[get_r8_index(new_str)];
                } else if (is_r16(new_str)) {
                    new_val = regs16[get_r16_index(new_str)];
                    is_16bit = true;
                } else if (is_number(new_str)) {
                    new_val = parse_int(new_str);
                } else {
                    throw runtime_error("CMPXCHG new_value must be register or immediate");
                }
                
                // Atomic compare and exchange on destination
                if (is_r8(dst)) {
                    int idx = get_r8_index(dst);
                    if (regs8[idx] == (u8)expected) {
                        regs8[idx] = (u8)new_val;
                        ZF = true;  // Success
                    } else {
                        ZF = false;  // Failed
                    }
                } else if (is_r16(dst)) {
                    int idx = get_r16_index(dst);
                    if (regs16[idx] == (u16)expected) {
                        regs16[idx] = (u16)new_val;
                        ZF = true;
                    } else {
                        ZF = false;
                    }
                } else if (is_mem(dst)) {
                    u32 addr = resolve_address(dst);
                    if (is_16bit) {
                        u16 current = mem_read16_at(addr);
                        if (current == (u16)expected) {
                            mem_write16_at(addr, (u16)new_val);
                            ZF = true;
                        } else {
                            ZF = false;
                        }
                    } else {
                        u8 current = mem_read8_at(addr);
                        if (current == (u8)expected) {
                            mem_write8_at(addr, (u8)new_val);
                            ZF = true;
                        } else {
                            ZF = false;
                        }
                    }
                } else {
                    throw runtime_error("CMPXCHG destination must be register or memory");
                }
                continue;
            }

            // XADD - Exchange and Add (atomic)
            // Syntax: XADD source destination
            // temp = destination; destination = destination + source; source = temp
            if (op == "XADD") {
                if (toks.size() < 3) throw runtime_error("XADD needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                // Both operands must be same size
                if (is_r8(src) && is_r8(dst)) {
                    int si = get_r8_index(src);
                    int di = get_r8_index(dst);
                    u8 temp = regs8[di];
                    regs8[di] = regs8[di] + regs8[si];
                    regs8[si] = temp;
                } else if (is_r16(src) && is_r16(dst)) {
                    int si = get_r16_index(src);
                    int di = get_r16_index(dst);
                    u16 temp = regs16[di];
                    regs16[di] = regs16[di] + regs16[si];
                    regs16[si] = temp;
                } else if (is_r8(src) && is_mem(dst)) {
                    int si = get_r8_index(src);
                    u32 addr = resolve_address(dst);
                    u8 temp = mem_read8_at(addr);
                    mem_write8_at(addr, temp + regs8[si]);
                    regs8[si] = temp;
                } else if (is_r16(src) && is_mem(dst)) {
                    int si = get_r16_index(src);
                    u32 addr = resolve_address(dst);
                    u16 temp = mem_read16_at(addr);
                    mem_write16_at(addr, temp + regs16[si]);
                    regs16[si] = temp;
                } else {
                    throw runtime_error("XADD: incompatible operands (must be reg-reg or reg-mem of same size)");
                }
                continue;
            }

            // IBTS - Insert Bit String (80386 early stepping only)
            // Syntax: IBTS base bit_offset source bit_count
            // Extracts bits from source register and inserts them into base
            // Starting at bit_offset for bit_count bits
            if (op == "IBTS") {
                if (toks.size() < 5) throw runtime_error("IBTS needs 4 arguments: base bit_offset source bit_count");
                
                string base = toks[1];
                string offset_str = toks[2];
                string source = toks[3];
                string count_str = toks[4];
                
                // Parse bit offset
                int bit_offset = 0;
                if (is_r8(offset_str)) bit_offset = regs8[get_r8_index(offset_str)];
                else if (is_number(offset_str)) bit_offset = parse_int(offset_str);
                else throw runtime_error("IBTS bit_offset must be register or immediate");
                
                // Parse bit count
                int bit_count = 0;
                if (is_r8(count_str)) bit_count = regs8[get_r8_index(count_str)];
                else if (is_number(count_str)) bit_count = parse_int(count_str);
                else throw runtime_error("IBTS bit_count must be register or immediate");
                
                // Clamp bit_count
                if (bit_count <= 0) continue;
                if (bit_count > 32) bit_count = 32;
                
                // Get source bits (from register)
                u32 source_bits = 0;
                if (is_r8(source)) source_bits = regs8[get_r8_index(source)];
                else if (is_r16(source)) source_bits = regs16[get_r16_index(source)];
                else throw runtime_error("IBTS source must be register");
                
                // Create mask for extraction
                u32 mask = (1U << bit_count) - 1;
                source_bits &= mask;
                
                // Insert into base operand
                if (is_r8(base)) {
                    int idx = get_r8_index(base);
                    bit_offset = bit_offset % 8;
                    if (bit_offset + bit_count > 8) bit_count = 8 - bit_offset;
                    
                    u8 dest = regs8[idx];
                    u8 insert_mask = ((1U << bit_count) - 1) << bit_offset;
                    dest = (dest & ~insert_mask) | ((source_bits << bit_offset) & insert_mask);
                    regs8[idx] = dest;
                    
                } else if (is_r16(base)) {
                    int idx = get_r16_index(base);
                    bit_offset = bit_offset % 16;
                    if (bit_offset + bit_count > 16) bit_count = 16 - bit_offset;
                    
                    u16 dest = regs16[idx];
                    u16 insert_mask = ((1U << bit_count) - 1) << bit_offset;
                    dest = (dest & ~insert_mask) | ((source_bits << bit_offset) & insert_mask);
                    regs16[idx] = dest;
                    
                } else if (is_mem(base)) {
                    u32 addr = resolve_address(base);
                    bit_offset = bit_offset % 8;
                    if (bit_offset + bit_count > 8) bit_count = 8 - bit_offset;
                    
                    u8 dest = mem_read8_at(addr);
                    u8 insert_mask = ((1U << bit_count) - 1) << bit_offset;
                    dest = (dest & ~insert_mask) | ((source_bits << bit_offset) & insert_mask);
                    mem_write8_at(addr, dest);
                    
                } else {
                    throw runtime_error("IBTS base must be register or memory");
                }
                
                continue;
            }

            // BSF - Bit Scan Forward (find index of first set bit from LSB)
            // Syntax: BSF source destination
            // Scans source from bit 0 upward, stores index of first 1-bit in destination
            // Sets ZF=1 if source is zero (no bits set), ZF=0 otherwise
            if (op == "BSF") {
                if (toks.size() < 3) throw runtime_error("BSF needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                int src_val = 0;
                bool is_16bit = false;
                
                // Get source value
                if (is_r8(src)) {
                    src_val = regs8[get_r8_index(src)];
                } else if (is_r16(src)) {
                    src_val = regs16[get_r16_index(src)];
                    is_16bit = true;
                } else if (is_mem(src)) {
                    u32 addr = resolve_address(src);
                    src_val = mem_read8_at(addr);
                } else if (is_number(src)) {
                    src_val = parse_int(src);
                } else {
                    throw runtime_error("BSF: unsupported source");
                }
                
                // Find first set bit
                if (src_val == 0) {
                    ZF = true;  // No bits set
                    // Destination is undefined, but we'll leave it unchanged
                } else {
                    ZF = false;
                    int bit_index = 0;
                    int max_bits = is_16bit ? 16 : 8;
                    
                    for (int i = 0; i < max_bits; i++) {
                        if (src_val & (1 << i)) {
                            bit_index = i;
                            break;
                        }
                    }
                    
                    // Store result in destination
                    if (is_r8(dst)) {
                        regs8[get_r8_index(dst)] = (u8)bit_index;
                    } else if (is_r16(dst)) {
                        regs16[get_r16_index(dst)] = (u16)bit_index;
                    } else {
                        throw runtime_error("BSF: destination must be register");
                    }
                }
                continue;
            }

            // BSR - Bit Scan Reverse (find index of last set bit from MSB)
            // Syntax: BSR source destination
            // Scans source from MSB downward, stores index of first 1-bit in destination
            // Sets ZF=1 if source is zero (no bits set), ZF=0 otherwise
            if (op == "BSR") {
                if (toks.size() < 3) throw runtime_error("BSR needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                int src_val = 0;
                bool is_16bit = false;
                
                // Get source value
                if (is_r8(src)) {
                    src_val = regs8[get_r8_index(src)];
                } else if (is_r16(src)) {
                    src_val = regs16[get_r16_index(src)];
                    is_16bit = true;
                } else if (is_mem(src)) {
                    u32 addr = resolve_address(src);
                    src_val = mem_read8_at(addr);
                } else if (is_number(src)) {
                    src_val = parse_int(src);
                } else {
                    throw runtime_error("BSR: unsupported source");
                }
                
                // Find last set bit (scan from MSB)
                if (src_val == 0) {
                    ZF = true;  // No bits set
                    // Destination is undefined, but we'll leave it unchanged
                } else {
                    ZF = false;
                    int bit_index = 0;
                    int max_bits = is_16bit ? 16 : 8;
                    
                    for (int i = max_bits - 1; i >= 0; i--) {
                        if (src_val & (1 << i)) {
                            bit_index = i;
                            break;
                        }
                    }
                    
                    // Store result in destination
                    if (is_r8(dst)) {
                        regs8[get_r8_index(dst)] = (u8)bit_index;
                    } else if (is_r16(dst)) {
                        regs16[get_r16_index(dst)] = (u16)bit_index;
                    } else {
                        throw runtime_error("BSR: destination must be register");
                    }
                }
                continue;
            }

            // BSWAP - Byte Swap (reverse byte order for endianness conversion)
            // Syntax: BSWAP operand
            // For 16-bit: 0x1234 becomes 0x3412
            // For 8-bit: No-op (undefined behavior in real x86, we'll just do nothing)
            if (op == "BSWAP") {
                if (toks.size() < 2) throw runtime_error("BSWAP needs 1 argument");
                string operand = toks[1];
                
                if (is_r8(operand)) {
                    // 8-bit BSWAP is undefined/no-op in real x86
                    // We'll just do nothing (some implementations zero it, but no-op is safer)
                    int idx = get_r8_index(operand);
                    // No operation for 8-bit
                    (void)idx;  // Suppress unused warning
                } else if (is_r16(operand)) {
                    int idx = get_r16_index(operand);
                    u16 val = regs16[idx];
                    // Swap bytes: 0xAABB becomes 0xBBAA
                    regs16[idx] = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
                } else if (is_mem(operand)) {
                    u32 addr = resolve_address(operand);
                    // Assume 16-bit memory operation
                    u16 val = mem_read16_at(addr);
                    u16 swapped = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
                    mem_write16_at(addr, swapped);
                } else {
                    throw runtime_error("BSWAP: operand must be register or memory");
                }
                continue;
            }

            // XBTS - Extract Bit String (80386 early stepping only)
            // Syntax: XBTS source bit_offset dest bit_count
            // Extracts bit_count bits from source starting at bit_offset
            // Stores result in dest register (zero-extended)
            if (op == "XBTS") {
                if (toks.size() < 5) throw runtime_error("XBTS needs 4 arguments: source bit_offset dest bit_count");
                
                string source = toks[1];
                string offset_str = toks[2];
                string dest = toks[3];
                string count_str = toks[4];
                
                // Parse bit offset
                int bit_offset = 0;
                if (is_r8(offset_str)) bit_offset = regs8[get_r8_index(offset_str)];
                else if (is_number(offset_str)) bit_offset = parse_int(offset_str);
                else throw runtime_error("XBTS bit_offset must be register or immediate");
                
                // Parse bit count
                int bit_count = 0;
                if (is_r8(count_str)) bit_count = regs8[get_r8_index(count_str)];
                else if (is_number(count_str)) bit_count = parse_int(count_str);
                else throw runtime_error("XBTS bit_count must be register or immediate");
                
                // Clamp bit_count
                if (bit_count <= 0) continue;
                if (bit_count > 32) bit_count = 32;
                
                // Extract from source
                u32 extracted = 0;
                
                if (is_r8(source)) {
                    bit_offset = bit_offset % 8;
                    if (bit_offset + bit_count > 8) bit_count = 8 - bit_offset;
                    extracted = (regs8[get_r8_index(source)] >> bit_offset) & ((1U << bit_count) - 1);
                    
                } else if (is_r16(source)) {
                    bit_offset = bit_offset % 16;
                    if (bit_offset + bit_count > 16) bit_count = 16 - bit_offset;
                    extracted = (regs16[get_r16_index(source)] >> bit_offset) & ((1U << bit_count) - 1);
                    
                } else if (is_mem(source)) {
                    u32 addr = resolve_address(source);
                    bit_offset = bit_offset % 8;
                    if (bit_offset + bit_count > 8) bit_count = 8 - bit_offset;
                    extracted = (mem_read8_at(addr) >> bit_offset) & ((1U << bit_count) - 1);
                    
                } else {
                    throw runtime_error("XBTS source must be register or memory");
                }
                
                // Store in destination register
                if (is_r8(dest)) {
                    regs8[get_r8_index(dest)] = (u8)extracted;
                } else if (is_r16(dest)) {
                    regs16[get_r16_index(dest)] = (u16)extracted;
                } else {
                    throw runtime_error("XBTS destination must be register");
                }
                
                continue;
            }

            if (op == "CALL") {
                if (toks.size() < 2) throw runtime_error("CALL needs label");
                string label = toks[1];
                if (!labels.count(label)) throw runtime_error("undefined label: " + label);

                if (SP < stack_base + 2) throw runtime_error("stack overflow");
                SP -= 2;
                mem_write16_at(SP, (u16)pc);

                pc = labels[label];
                continue;
            }

            if (op == "RET") {
                if (SP + 2 > stack_base + stack_size) throw runtime_error("stack underflow");

                u16 ret_addr = mem_read16_at(SP);
                SP += 2;
                pc = ret_addr;
                continue;
            }

            if (op == "POP") {
                if (toks.size() < 2) throw runtime_error("POP needs 1 argument");
                string B = toks[1];

                if (is_r8(B)) {
                    if (SP >= stack_base + stack_size) throw runtime_error("stack underflow");
                    regs8[get_r8_index(B)] = mem_read8_at(SP);
                    SP += 1;
                } else if (is_r16(B)) {
                    if (SP + 2 > stack_base + stack_size) throw runtime_error("stack underflow");
                    regs16[get_r16_index(B)] = mem_read16_at(SP);
                    SP += 2;
                } else throw runtime_error("unsupported POP target: " + B);

                continue;
            }

            // POPCNT - Population Count (count number of 1 bits)
            // Syntax: POPCNT source destination
            // Counts the number of set bits in source, stores count in destination
            if (op == "POPCNT") {
                if (toks.size() < 3) throw runtime_error("POPCNT needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                int src_val = 0;
                bool is_16bit = false;
                
                // Get source value
                if (is_r8(src)) {
                    src_val = regs8[get_r8_index(src)];
                } else if (is_r16(src)) {
                    src_val = regs16[get_r16_index(src)];
                    is_16bit = true;
                } else if (is_mem(src)) {
                    u32 addr = resolve_address(src);
                    src_val = mem_read8_at(addr);
                } else if (is_number(src)) {
                    src_val = parse_int(src);
                } else {
                    throw runtime_error("POPCNT: unsupported source");
                }
                
                // Count set bits
                int count = 0;
                int max_bits = is_16bit ? 16 : 8;
                
                for (int i = 0; i < max_bits; i++) {
                    if (src_val & (1 << i)) {
                        count++;
                    }
                }
                
                // Set ZF if result is zero
                ZF = (count == 0);
                
                // Store result in destination
                if (is_r8(dst)) {
                    regs8[get_r8_index(dst)] = (u8)count;
                } else if (is_r16(dst)) {
                    regs16[get_r16_index(dst)] = (u16)count;
                } else {
                    throw runtime_error("POPCNT: destination must be register");
                }
                
                continue;
            }

            // LOOP - Decrement counter and jump if not zero
            // Syntax: LOOP counter label
            // Decrements counter, jumps to label if counter != 0
            if (op == "LOOP") {
                if (toks.size() < 3) throw runtime_error("LOOP needs 2 arguments: counter and label");
                string counter = toks[1], label = toks[2];
    
                // Decrement the counter
                if (is_r8(counter)) {
                    int idx = get_r8_index(counter);
                    regs8[idx] = (u8)(regs8[idx] - 1);
        
                    // Jump if not zero
                    if (regs8[idx] != 0) {
                        if (!labels.count(label)) throw runtime_error("undefined label: " + label);
                        pc = labels[label];
                    }
                } else if (is_r16(counter)) {
                    int idx = get_r16_index(counter);
                    regs16[idx] = (u16)(regs16[idx] - 1);
        
                    // Jump if not zero
                    if (regs16[idx] != 0) {
                        if (!labels.count(label)) throw runtime_error("undefined label: " + label);
                        pc = labels[label];
                    }
                } else {
                    throw runtime_error("LOOP counter must be r8N or r16N register");
                }
                continue;
            }

            // BT - Bit Test (test bit, set CF to bit value)
            // Syntax: BT bit_position operand
            if (op == "BT") {
                if (toks.size() < 3) throw runtime_error("BT needs 2 arguments");
                string bit_str = toks[1], operand = toks[2];
                
                int bit_pos = 0;
                if (is_r8(bit_str)) bit_pos = regs8[get_r8_index(bit_str)];
                else if (is_number(bit_str)) bit_pos = parse_int(bit_str);
                else throw runtime_error("BT bit position must be register or immediate");
                
                if (is_r8(operand)) {
                    bit_pos = bit_pos % 8;
                    CF = ((regs8[get_r8_index(operand)] >> bit_pos) & 1) != 0;
                } else if (is_r16(operand)) {
                    bit_pos = bit_pos % 16;
                    CF = ((regs16[get_r16_index(operand)] >> bit_pos) & 1) != 0;
                } else if (is_mem(operand)) {
                    bit_pos = bit_pos % 8;
                    u32 addr = resolve_address(operand);
                    CF = ((mem_read8_at(addr) >> bit_pos) & 1) != 0;
                } else {
                    throw runtime_error("BT operand must be register or memory");
                }
                continue;
            }

            // BTS - Bit Test and Set (test bit, set CF, then set bit to 1)
            // Syntax: BTS bit_position operand
            if (op == "BTS") {
                if (toks.size() < 3) throw runtime_error("BTS needs 2 arguments");
                string bit_str = toks[1], operand = toks[2];
                
                int bit_pos = 0;
                if (is_r8(bit_str)) bit_pos = regs8[get_r8_index(bit_str)];
                else if (is_number(bit_str)) bit_pos = parse_int(bit_str);
                else throw runtime_error("BTS bit position must be register or immediate");
                
                if (is_r8(operand)) {
                    int idx = get_r8_index(operand);
                    bit_pos = bit_pos % 8;
                    CF = ((regs8[idx] >> bit_pos) & 1) != 0;
                    regs8[idx] |= (1 << bit_pos);
                } else if (is_r16(operand)) {
                    int idx = get_r16_index(operand);
                    bit_pos = bit_pos % 16;
                    CF = ((regs16[idx] >> bit_pos) & 1) != 0;
                    regs16[idx] |= (1 << bit_pos);
                } else if (is_mem(operand)) {
                    bit_pos = bit_pos % 8;
                    u32 addr = resolve_address(operand);
                    u8 val = mem_read8_at(addr);
                    CF = ((val >> bit_pos) & 1) != 0;
                    mem_write8_at(addr, val | (1 << bit_pos));
                } else {
                    throw runtime_error("BTS operand must be register or memory");
                }
                continue;
            }

            // BTR - Bit Test and Reset (test bit, set CF, then set bit to 0)
            // Syntax: BTR bit_position operand
            if (op == "BTR") {
                if (toks.size() < 3) throw runtime_error("BTR needs 2 arguments");
                string bit_str = toks[1], operand = toks[2];
                
                int bit_pos = 0;
                if (is_r8(bit_str)) bit_pos = regs8[get_r8_index(bit_str)];
                else if (is_number(bit_str)) bit_pos = parse_int(bit_str);
                else throw runtime_error("BTR bit position must be register or immediate");
                
                if (is_r8(operand)) {
                    int idx = get_r8_index(operand);
                    bit_pos = bit_pos % 8;
                    CF = ((regs8[idx] >> bit_pos) & 1) != 0;
                    regs8[idx] &= ~(1 << bit_pos);
                } else if (is_r16(operand)) {
                    int idx = get_r16_index(operand);
                    bit_pos = bit_pos % 16;
                    CF = ((regs16[idx] >> bit_pos) & 1) != 0;
                    regs16[idx] &= ~(1 << bit_pos);
                } else if (is_mem(operand)) {
                    bit_pos = bit_pos % 8;
                    u32 addr = resolve_address(operand);
                    u8 val = mem_read8_at(addr);
                    CF = ((val >> bit_pos) & 1) != 0;
                    mem_write8_at(addr, val & ~(1 << bit_pos));
                } else {
                    throw runtime_error("BTR operand must be register or memory");
                }
                continue;
            }

            // BTC - Bit Test and Complement (test bit, set CF, then flip bit)
            // Syntax: BTC bit_position operand
            if (op == "BTC") {
                if (toks.size() < 3) throw runtime_error("BTC needs 2 arguments");
                string bit_str = toks[1], operand = toks[2];
                
                int bit_pos = 0;
                if (is_r8(bit_str)) bit_pos = regs8[get_r8_index(bit_str)];
                else if (is_number(bit_str)) bit_pos = parse_int(bit_str);
                else throw runtime_error("BTC bit position must be register or immediate");
                
                if (is_r8(operand)) {
                    int idx = get_r8_index(operand);
                    bit_pos = bit_pos % 8;
                    CF = ((regs8[idx] >> bit_pos) & 1) != 0;
                    regs8[idx] ^= (1 << bit_pos);
                } else if (is_r16(operand)) {
                    int idx = get_r16_index(operand);
                    bit_pos = bit_pos % 16;
                    CF = ((regs16[idx] >> bit_pos) & 1) != 0;
                    regs16[idx] ^= (1 << bit_pos);
                } else if (is_mem(operand)) {
                    bit_pos = bit_pos % 8;
                    u32 addr = resolve_address(operand);
                    u8 val = mem_read8_at(addr);
                    CF = ((val >> bit_pos) & 1) != 0;
                    mem_write8_at(addr, val ^ (1 << bit_pos));
                } else {
                    throw runtime_error("BTC operand must be register or memory");
                }
                continue;
            }

            // MOVZX - Move with Zero Extension (8-bit to 16-bit)
            // Syntax: MOVZX source destination
            // Moves 8-bit value to 16-bit register, zero-extending
            if (op == "MOVZX") {
                if (toks.size() < 3) throw runtime_error("MOVZX needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                u8 val = 0;
                if (is_r8(src)) {
                    val = regs8[get_r8_index(src)];
                } else if (is_mem(src)) {
                    u32 addr = resolve_address(src);
                    val = mem_read8_at(addr);
                } else if (is_number(src)) {
                    val = (u8)parse_int(src);
                } else {
                    throw runtime_error("MOVZX source must be r8, memory, or immediate");
                }
                
                if (!is_r16(dst)) {
                    throw runtime_error("MOVZX destination must be r16");
                }
                
                regs16[get_r16_index(dst)] = (u16)val;  // Zero extend
                continue;
            }

            // MOVSX - Move with Sign Extension (8-bit to 16-bit)
            // Syntax: MOVSX source destination
            // Moves 8-bit value to 16-bit register, sign-extending
            if (op == "MOVSX") {
                if (toks.size() < 3) throw runtime_error("MOVSX needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                i8 val = 0;
                if (is_r8(src)) {
                    val = (i8)regs8[get_r8_index(src)];
                } else if (is_mem(src)) {
                    u32 addr = resolve_address(src);
                    val = (i8)mem_read8_at(addr);
                } else if (is_number(src)) {
                    val = (i8)parse_int(src);
                } else {
                    throw runtime_error("MOVSX source must be r8, memory, or immediate");
                }
                
                if (!is_r16(dst)) {
                    throw runtime_error("MOVSX destination must be r16");
                }
                
                regs16[get_r16_index(dst)] = (u16)(i16)val;  // Sign extend
                continue;
            }

            // MOVS - Move String (copy from [source] to [destination])
            // Syntax: MOVS source_reg dest_reg count_reg
            // Copies 'count' bytes from address in source_reg to address in dest_reg
            if (op == "MOVS") {
                if (toks.size() < 4) throw runtime_error("MOVS needs 3 arguments: source_reg dest_reg count_reg");
                string src_reg = toks[1], dst_reg = toks[2], count_reg = toks[3];
                
                // Get source address
                u32 src_addr = 0;
                if (is_r16(src_reg)) src_addr = regs16[get_r16_index(src_reg)];
                else if (is_r8(src_reg)) src_addr = regs8[get_r8_index(src_reg)];
                else throw runtime_error("MOVS: source must be register containing address");
                
                // Get destination address
                u32 dst_addr = 0;
                if (is_r16(dst_reg)) dst_addr = regs16[get_r16_index(dst_reg)];
                else if (is_r8(dst_reg)) dst_addr = regs8[get_r8_index(dst_reg)];
                else throw runtime_error("MOVS: destination must be register containing address");
                
                // Get count
                u32 count = 0;
                if (is_r16(count_reg)) count = regs16[get_r16_index(count_reg)];
                else if (is_r8(count_reg)) count = regs8[get_r8_index(count_reg)];
                else if (is_number(count_reg)) count = parse_int(count_reg);
                else throw runtime_error("MOVS: count must be register or immediate");
                
                // Copy bytes
                for (u32 i = 0; i < count; i++) {
                    u8 byte = mem_read8_at(src_addr + i);
                    mem_write8_at(dst_addr + i, byte);
                }
                
                continue;
            }

            // CMPS - Compare String (compare two memory blocks)
            // Syntax: CMPS source_reg dest_reg count_reg
            // Compares 'count' bytes, sets ZF=1 if equal, ZF=0 if different
            if (op == "CMPS") {
                if (toks.size() < 4) throw runtime_error("CMPS needs 3 arguments: source_reg dest_reg count_reg");
                string src_reg = toks[1], dst_reg = toks[2], count_reg = toks[3];
                
                // Get source address
                u32 src_addr = 0;
                if (is_r16(src_reg)) src_addr = regs16[get_r16_index(src_reg)];
                else if (is_r8(src_reg)) src_addr = regs8[get_r8_index(src_reg)];
                else throw runtime_error("CMPS: source must be register containing address");
                
                // Get destination address
                u32 dst_addr = 0;
                if (is_r16(dst_reg)) dst_addr = regs16[get_r16_index(dst_reg)];
                else if (is_r8(dst_reg)) dst_addr = regs8[get_r8_index(dst_reg)];
                else throw runtime_error("CMPS: destination must be register containing address");
                
                // Get count
                u32 count = 0;
                if (is_r16(count_reg)) count = regs16[get_r16_index(count_reg)];
                else if (is_r8(count_reg)) count = regs8[get_r8_index(count_reg)];
                else if (is_number(count_reg)) count = parse_int(count_reg);
                else throw runtime_error("CMPS: count must be register or immediate");
                
                // Compare bytes
                ZF = true;  // Assume equal
                for (u32 i = 0; i < count; i++) {
                    u8 byte1 = mem_read8_at(src_addr + i);
                    u8 byte2 = mem_read8_at(dst_addr + i);
                    if (byte1 != byte2) {
                        ZF = false;
                        SF = (byte2 < byte1);  // Set sign based on comparison
                        break;
                    }
                }
                
                continue;
            }

            // SCAS - Scan String (search for value in memory block)
            // Syntax: SCAS value address_reg count_reg result_reg
            // Searches for 'value' in 'count' bytes starting at address
            // Stores index of first match in result_reg, sets ZF=1 if found
            if (op == "SCAS") {
                if (toks.size() < 5) throw runtime_error("SCAS needs 4 arguments: value address_reg count_reg result_reg");
                string value_str = toks[1], addr_reg = toks[2], count_reg = toks[3], result_reg = toks[4];
                
                // Get value to search for
                u8 search_val = 0;
                if (is_r8(value_str)) search_val = regs8[get_r8_index(value_str)];
                else if (is_number(value_str)) search_val = (u8)parse_int(value_str);
                else throw runtime_error("SCAS: search value must be r8 or immediate");
                
                // Get address
                u32 addr = 0;
                if (is_r16(addr_reg)) addr = regs16[get_r16_index(addr_reg)];
                else if (is_r8(addr_reg)) addr = regs8[get_r8_index(addr_reg)];
                else throw runtime_error("SCAS: address must be register");
                
                // Get count
                u32 count = 0;
                if (is_r16(count_reg)) count = regs16[get_r16_index(count_reg)];
                else if (is_r8(count_reg)) count = regs8[get_r8_index(count_reg)];
                else if (is_number(count_reg)) count = parse_int(count_reg);
                else throw runtime_error("SCAS: count must be register or immediate");
                
                // Search for value
                ZF = false;  // Assume not found
                u32 found_index = 0;
                for (u32 i = 0; i < count; i++) {
                    u8 byte = mem_read8_at(addr + i);
                    if (byte == search_val) {
                        ZF = true;  // Found
                        found_index = i;
                        break;
                    }
                }
                
                // Store result index
                if (is_r8(result_reg)) {
                    regs8[get_r8_index(result_reg)] = (u8)found_index;
                } else if (is_r16(result_reg)) {
                    regs16[get_r16_index(result_reg)] = (u16)found_index;
                } else {
                    throw runtime_error("SCAS: result must be register");
                }
                
                continue;
            }

            // LODS - Load String (load byte from memory to register)
            // Syntax: LODS address_reg dest_reg [offset]
            // Loads byte from [address + offset] into dest_reg
            if (op == "LODS") {
                if (toks.size() < 3) throw runtime_error("LODS needs at least 2 arguments: address_reg dest_reg [offset]");
                string addr_reg = toks[1], dest_reg = toks[2];
                string offset_str = (toks.size() >= 4) ? toks[3] : "0";
                
                // Get address
                u32 addr = 0;
                if (is_r16(addr_reg)) addr = regs16[get_r16_index(addr_reg)];
                else if (is_r8(addr_reg)) addr = regs8[get_r8_index(addr_reg)];
                else throw runtime_error("LODS: address must be register");
                
                // Get offset
                u32 offset = 0;
                if (is_r8(offset_str)) offset = regs8[get_r8_index(offset_str)];
                else if (is_r16(offset_str)) offset = regs16[get_r16_index(offset_str)];
                else if (is_number(offset_str)) offset = parse_int(offset_str);
                else throw runtime_error("LODS: offset must be register or immediate");
                
                // Load byte
                u8 byte = mem_read8_at(addr + offset);
                
                // Store in destination
                if (is_r8(dest_reg)) {
                    regs8[get_r8_index(dest_reg)] = byte;
                } else if (is_r16(dest_reg)) {
                    regs16[get_r16_index(dest_reg)] = byte;
                } else {
                    throw runtime_error("LODS: destination must be register");
                }
                
                continue;
            }

            // STOS - Store String (fill memory with value)
            // Syntax: STOS value address_reg count_reg
            // Fills 'count' bytes starting at address with value
            if (op == "STOS") {
                if (toks.size() < 4) throw runtime_error("STOS needs 3 arguments: value address_reg count_reg");
                string value_str = toks[1], addr_reg = toks[2], count_reg = toks[3];
                
                // Get value to store
                u8 store_val = 0;
                if (is_r8(value_str)) store_val = regs8[get_r8_index(value_str)];
                else if (is_number(value_str)) store_val = (u8)parse_int(value_str);
                else throw runtime_error("STOS: value must be r8 or immediate");
                
                // Get address
                u32 addr = 0;
                if (is_r16(addr_reg)) addr = regs16[get_r16_index(addr_reg)];
                else if (is_r8(addr_reg)) addr = regs8[get_r8_index(addr_reg)];
                else throw runtime_error("STOS: address must be register");
                
                // Get count
                u32 count = 0;
                if (is_r16(count_reg)) count = regs16[get_r16_index(count_reg)];
                else if (is_r8(count_reg)) count = regs8[get_r8_index(count_reg)];
                else if (is_number(count_reg)) count = parse_int(count_reg);
                else throw runtime_error("STOS: count must be register or immediate");
                
                // Fill memory
                for (u32 i = 0; i < count; i++) {
                    mem_write8_at(addr + i, store_val);
                }
                
                continue;
            }

// CPUID - CPU Identification
            // Syntax: CPUID function_id
            // Returns CPU information based on function_id in various registers
            // Function 0: Vendor string and max function
            // Function 1: CPU features and family info
            // Function 2: Cache information
            // Function 0x80000000: Extended function support
            if (op == "CPUID") {
                if (toks.size() < 2) throw runtime_error("CPUID needs 1 argument (function_id)");
                string func_str = toks[1];
                
                u32 function = 0;
                if (is_r8(func_str)) function = regs8[get_r8_index(func_str)];
                else if (is_r16(func_str)) function = regs16[get_r16_index(func_str)];
                else if (is_number(func_str)) function = parse_int(func_str);
                else throw runtime_error("CPUID: function must be register or immediate");
                
                // Clear output registers (r16_0 = EAX, r16_1 = EBX, r16_2 = ECX, r16_3 = EDX)
                regs16[0] = 0;
                regs16[1] = 0;
                regs16[2] = 0;
                regs16[3] = 0;
                
                switch (function) {
                    case 0:
                        // Function 0: Vendor ID and maximum function number
                        regs16[0] = 2;  // Max basic function supported
                        // Vendor string "VirtualCPU16" split across EBX, EDX, ECX
                        // "Virt" in EBX
                        regs16[1] = ('V' | ('i' << 8));
                        regs8[4] = 'r';
                        regs8[5] = 't';
                        // "ualC" in EDX  
                        regs16[3] = ('u' | ('a' << 8));
                        regs8[6] = 'l';
                        regs8[7] = 'C';
                        // "PU16" in ECX
                        regs16[2] = ('P' | ('U' << 8));
                        regs8[4] = '1';
                        regs8[5] = '6';
                        break;
                        
                    case 1: {
                        // Function 1: Processor Info and Feature Bits
                        // EAX: Version Information
                        // Family = 6, Model = 1, Stepping = 0
                        regs16[0] = (6 << 8) | (1 << 4) | 0;
                        
                        // EBX: Brand Index, CLFLUSH line size, Max APIC IDs, Initial APIC ID
                        regs16[1] = (0 << 8) | 8;  // CLFLUSH = 8
                        
                        // ECX: Feature flags (extended)
                        // Bit 0: SSE3, Bit 9: SSSE3, Bit 19: SSE4.1, Bit 20: SSE4.2
                        // Bit 23: POPCNT
                        u16 ecx_features = 0;
                        ecx_features |= (1 << 0);   // SSE3 (simulated)
                        ecx_features |= (1 << 9);   // SSSE3 (simulated)
                        // We actually have POPCNT, but bit 23 doesn't fit in 16-bit
                        regs16[2] = ecx_features;
                        
                        // EDX: Feature flags (standard)
                        // Bit 0: FPU, Bit 4: TSC, Bit 15: CMOV, Bit 23: MMX
                        u16 edx_features = 0;
                        edx_features |= (1 << 0);   // FPU - we have f32/f64
                        edx_features |= (1 << 4);   // TSC (timestamp counter)
                        edx_features |= (1 << 15);  // CMOV - we have conditional moves
                        regs16[3] = edx_features;
                        break;
                    }
                        
                    case 2:
                        // Function 2: Cache and TLB Information
                        // Simplified: Report L1 cache info
                        regs16[0] = 0x01;  // Cache descriptor
                        regs16[1] = 0x2000; // 8KB L1 data cache (simulated)
                        regs16[2] = 0x2000; // 8KB L1 instruction cache (simulated)
                        regs16[3] = 0x0000; // No L2 cache info
                        break;
                        
                    case 0x8000:
                        // Function 0x80000000: Extended Function Support
                        regs16[0] = 0x8004; // Max extended function (supports up to 0x80000004)
                        regs16[1] = 0x0000;
                        regs16[2] = 0x0000;
                        regs16[3] = 0x0000;
                        break;
                        
                    case 0x8001:
                        // Function 0x80000001: Extended Processor Info
                        regs16[0] = 0x0000;
                        regs16[1] = 0x0000;
                        // ECX: Extended features (LZCNT, etc.)
                        regs16[2] = 0x0000;
                        // EDX: Extended features
                        regs16[3] = 0x0000;
                        break;
                        
                    case 0x8002:
                    case 0x8003:
                    case 0x8004:
                        // Processor Brand String (24 bytes across 3 calls, 8 bytes each)
                        // "VirtualCPU v1.0 Muerte"
                        if (function == 0x8002) {
                            // First 8 bytes: "VirtualC"
                            regs16[0] = ('V' | ('i' << 8));
                            regs16[1] = ('r' | ('t' << 8));
                            regs16[2] = ('u' | ('a' << 8));
                            regs16[3] = ('l' | ('C' << 8));
                        } else if (function == 0x8003) {
                            // Next 8 bytes: "PU v1.0 "
                            regs16[0] = ('P' | ('U' << 8));
                            regs16[1] = (' ' | ('v' << 8));
                            regs16[2] = ('1' | ('.' << 8));
                            regs16[3] = ('0' | (' ' << 8));
                        } else {
                            // Last 8 bytes: "Muerte  " (6 chars + 2 spaces)
                            regs16[0] = ('M' | ('u' << 8));
                            regs16[1] = ('e' | ('r' << 8));
                            regs16[2] = ('t' | ('e' << 8));
                            regs16[3] = (' ' | (' ' << 8));
                        }
                        break;
                        
                    default:
                        // Unknown function - return zeros
                        regs16[0] = 0;
                        regs16[1] = 0;
                        regs16[2] = 0;
                        regs16[3] = 0;
                        break;
                }
                
                continue;
            }
            throw runtime_error("unknown instruction: " + op);
        }
    }
};