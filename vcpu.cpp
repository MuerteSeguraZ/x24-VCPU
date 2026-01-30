#include <bits/stdc++.h>
#include "vcfs.c"
using namespace std;

unordered_map<string, size_t> labels;

using u8  = uint8_t;
using u16 = uint16_t;
using i8  = int8_t;
using i16 = int16_t;
using u32 = uint32_t;

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
    u32 SP = 0; 
    
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

    // memory layout
    size_t program_region = 0;
    size_t program_size = 0;
    size_t ram16_offset = 0;
    size_t ram16_size = 0;
    size_t ram8_offset = 0;
    size_t ram8_size = 256;

    // program
    vector<string> program;

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
            string line = trim(program[pc]);

            if (line.empty() || line[0] == '#' || line.back() == ':') {
                pc++;
                continue;
            }

            auto toks = split_tok(line);
            if (toks.empty()) {
                pc++;
                continue;
            }

            string op = toks[0];

            // QUIT / EXIT
            if (op == "QUIT" || op == "EXIT") {
                cout << "Program exited via QUIT.\n";
                return;
            }

            pc++; 

            if (op == "NOP") {
                // Literally do nothing
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
                            if (sign == 'S') regs8[bi] = (u8)((i8)bval * (i8)aval);
                            else regs8[bi] = (u8)((u8)bval * (u8)aval);
                        } else if (opcode == "DIV") {
                            if (aval == 0) throw runtime_error("division by zero");
                            if (sign == 'S') regs8[bi] = (u8)((i8)bval / (i8)aval);
                            else regs8[bi] = (u8)((u8)bval / (u8)aval);
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
                            if (sign == 'S') mem_write8_at(addr, (u8)((i8)bval * (i8)aval));
                            else mem_write8_at(addr, (u8)((u8)bval * (u8)aval));
                        } else if (opcode == "DIV") {
                            if (aval == 0) throw runtime_error("division by zero");
                            if (sign == 'S') mem_write8_at(addr, (u8)((i8)bval / (i8)aval));
                            else mem_write8_at(addr, (u8)((u8)bval / (u8)aval));
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
                            if (sign == 'S') regs16[bi] = (u16)((i16)bval * (i16)aval);
                            else regs16[bi] = (u16)((u16)bval * (u16)aval);
                        } else if (opcode == "DIV") {
                            if (aval == 0) throw runtime_error("division by zero");
                            if (sign == 'S') regs16[bi] = (u16)((i16)bval / (i16)aval);
                            else regs16[bi] = (u16)((u16)bval / (u16)aval);
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
                            if (sign == 'S') mem_write16_at(addr, (u16)((i16)bval * (i16)aval));
                            else mem_write16_at(addr, (u16)((u16)bval * (u16)aval));
                        } else if (opcode == "DIV") {
                            if (aval == 0) throw runtime_error("division by zero");
                            if (sign == 'S') mem_write16_at(addr, (u16)((i16)bval / (i16)aval));
                            else mem_write16_at(addr, (u16)((u16)bval / (u16)aval));
                        }
                    } else {
                        throw runtime_error("B must be r16N or memory for 16-bit op: " + B);
                    }
                } else {
                    throw runtime_error("unknown size prefix in opcode: " + op);
                }
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
                }
                
                u8 val = mem_read8_at(addr);
                if (!is_r8(B)) throw runtime_error("LREAD target must be r8N");
                int bi = get_r8_index(B);
                regs8[bi] = val;
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
                    if (op == "INC") regs8[idx] = (u8)(regs8[idx] + 1);
                    else regs8[idx] = (u8)(regs8[idx] - 1);
                } else if (is_r16(A)) {
                    int idx = get_r16_index(A);
                    if (op == "INC") regs16[idx] = (u16)(regs16[idx] + 1);
                    else regs16[idx] = (u16)(regs16[idx] - 1);
                } else if (is_mem(A)) {
                    u32 addr = resolve_address(A);
                    u8 val = mem_read8_at(addr);
                    if (op == "INC") mem_write8_at(addr, val + 1);
                    else mem_write8_at(addr, val - 1);
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
                    val = mem_read8_at(addr);
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
            throw runtime_error("unknown instruction: " + op);
        }
    }
};