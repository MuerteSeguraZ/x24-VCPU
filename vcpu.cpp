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
    if (a==string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b-a+1);
}

static vector<string> split_tok(const string &line) {
    vector<string> t;
    string cur;
    bool inbr = false;
    for (size_t i=0;i<line.size();++i){
        char c=line[i];
        if (c=='[') inbr=true;
        if (c==']') inbr=false;
        if (!inbr && isspace((unsigned char)c)) { if(!cur.empty()){t.push_back(cur); cur.clear();} }
        else cur.push_back(c);
    }
    if(!cur.empty()) t.push_back(cur);
    return t;
}

struct CPU {
    // registers
    array<u8, 32> regs8{};
    array<u16, 32> regs16{};
    u32 SP = 0; 
    // memory (external)
    vector<u8> mem;
    size_t mem_size = 65536;
    size_t stack_base = 0; // base address of the stack
    size_t stack_size = 1024; // configurable stack size

    void set_flags(int a, int b) {
    int res = b - a;
    ZF = (res == 0);
    SF = (res < 0);
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

    bool ZF = false;
    bool SF = false;

    // layout config
    size_t program_region = 0; // program placed at start
    size_t program_size = 0;
    size_t ram16_offset = 0; // start of 16-bit-addressable RAM
    size_t ram16_size = 0;
    size_t ram8_offset = 0;  // start of 8-bit limited RAM (256 bytes max)
    size_t ram8_size = 256;  // configured

    // program (text lines)
    vector<string> program;

CPU(size_t full_mem = 65536, size_t ram16_sz = 4096, size_t ram8_sz = 256) {
    if (full_mem < ram8_sz + 1) throw runtime_error("memory too small");
    mem_size = full_mem;
    mem.assign(mem_size, 0);

    // 8-bit RAM
    ram8_size = min<size_t>(ram8_sz, 256);
    ram8_offset = mem_size - ram8_size;  // place at top of memory

    // stack
    stack_size = 1024;                    // default 1 KB stack
    if (stack_size > ram8_offset)        // ensure it doesn't overlap 8-bit RAM
        stack_size = ram8_offset;

    stack_base = ram8_offset - stack_size; // stack sits just below 8-bit RAM
    SP = stack_base + stack_size;          // SP points to top (stack grows down)

    // program & 16-bit RAM
    program_region = 0;
    program_size = 0;
    ram16_offset = 0;                     // will set after loading program
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
        if (s.rfind("r8",0)==0) {
            string num = s.substr(2);
            try { int n=stoi(num); return n>=0 && n<32; } catch(...) {}
        }
        return false;
    }
    bool is_r16(const string &s) {
        if (s.size() < 4) return false;
        if (s.rfind("r16",0)==0) {
            string num = s.substr(3);
            try { int n=stoi(num); return n>=0 && n<32; } catch(...) {}
        }
        return false;
    }
    bool is_mem(const string &s) {
        return s.size()>=3 && s.front()=='[' && s.back()==']';
    }
    bool is_number(const string &s) {
        if (s.empty()) return false;
        try {
            size_t idx=0;
            if (s.size()>2 && s[0]=='0' && (s[1]=='x' || s[1]=='X')) {
                stoi(s,nullptr,16);
            } else {
                stoi(s,nullptr,0);
            }
            return true;
        } catch(...) {}
        return false;
    }

    int parse_int(const string &tok) {
        try {
            if (tok.size()>2 && tok[0]=='0' && (tok[1]=='x' || tok[1]=='X')) return stoi(tok,nullptr,16);
            return stoi(tok,nullptr,0);
        } catch(...) { throw runtime_error("invalid integer: "+tok); }
    }

    u32 resolve_address(const string &memtok) {
        if (!is_mem(memtok)) throw runtime_error("not memory token: "+memtok);
        string inside = memtok.substr(1, memtok.size()-2);
        inside = trim(inside);
        if (is_r8(inside)) {
            int idx = stoi(inside.substr(2));
            return regs8[idx];
        } else if (is_r16(inside)) {
            int idx = stoi(inside.substr(3));
            return regs16[idx];
        } else if (is_number(inside)) {
            int v = parse_int(inside);
            if (v < 0) throw runtime_error("negative address not supported");
            return (u32)v;
        } else {
            throw runtime_error("unsupported memory address token: "+inside);
        }
    }

    u8 mem_read8_at(u32 addr) {
        if (addr >= mem_size) throw runtime_error("memory read8 out of bounds");
        return mem[addr];
    }
    void mem_write8_at(u32 addr, u8 val) {
        if (addr >= mem_size) throw runtime_error("memory write8 out of bounds");
        mem[addr] = val;
    }
    u16 mem_read16_at(u32 addr) {
        if (addr+1 >= mem_size) throw runtime_error("memory read16 out of bounds");
        // little endian
        return (u16)mem[addr] | ((u16)mem[addr+1] << 8);
    }
    void mem_write16_at(u32 addr, u16 val) {
        if (addr+1 >= mem_size) throw runtime_error("memory write16 out of bounds");
        mem[addr] = (u8)(val & 0xFF);
        mem[addr+1] = (u8)((val >> 8) & 0xFF);
    }

    // Execution entrypoint
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

            // Arithmetic ops formats: <FlagAdd> A B
            // Flag prefix: two letters: size(L/H), s/u (S/U). Example: LSADD, HUADD, etc.
            if ((op.size()==5 || op.size()==6) && (op.find("ADD")!=string::npos || op.find("SUB")!=string::npos || op.find("MUL")!=string::npos || op.find("DIV")!=string::npos)) {
                // decode
                char size = op[0]; // 'L' or 'H'
                char sign = op[1]; // 'S' or 'U' (signed/unsigned)
                string body = op.substr(2); // e.g., "ADD" or "SADD"? We'll accept ops where body contains ADD/SUB/MUL/DIV
                string opcode;
                if (body=="ADD" || body=="SUB" || body=="MUL" || body=="DIV") opcode = body;
                else opcode = body; // fallback

                if (toks.size() < 3) throw runtime_error("not enough args for arithmetic");
                string A = toks[1], B = toks[2];
                if (size=='L') {
                    i32_t:;
                    int aval = 0;
                    if (is_r8(A)) aval = (int)regs8[stoi(A.substr(2))];
                    else if (is_number(A)) aval = parse_int(A) & 0xFF;
                    else if (is_mem(A)) { aval = mem_read8_at(resolve_address(A)); }
                    else throw runtime_error("unsupported A for 8-bit op: "+A);
                    if (is_r8(B)) {
                        int bi = stoi(B.substr(2));
                        int bval = regs8[bi];
                        if (opcode=="ADD") {
                            if (sign=='S') {
                                i8 ra = (i8)aval;
                                i8 rb = (i8)bval;
                                i8 res = (i8)(rb + ra);
                                regs8[bi] = (u8)res;
                            } else {
                                u8 res = (u8)( (u8)bval + (u8)aval );
                                regs8[bi] = res;
                            }
                        } else if (opcode=="SUB") {
                            if (sign=='S') {
                                i8 ra=(i8)aval, rb=(i8)bval;
                                regs8[bi] = (u8)( (i8)(rb - ra) );
                            } else regs8[bi] = (u8)( (u8)bval - (u8)aval );
                        } else if (opcode=="MUL") {
                            if (sign=='S') regs8[bi] = (u8)( (i8)bval * (i8)aval );
                            else regs8[bi] = (u8)( (u8)bval * (u8)aval );
                        } else if (opcode=="DIV") {
                            if (aval==0) throw runtime_error("division by zero");
                            if (sign=='S') regs8[bi] = (u8)( (i8)bval / (i8)aval );
                            else regs8[bi] = (u8)( (u8)bval / (u8)aval );
                        } else throw runtime_error("unknown opcode "+opcode);
                    } else if (is_mem(B)) {
                        u32 addr = resolve_address(B);
                        // write back to memory 8-bit
                        if (opcode=="ADD") {
                            if (sign=='S') {
                                i8 prev = (i8)mem_read8_at(addr);
                                i8 res = prev + (i8)aval;
                                mem_write8_at(addr, (u8)res);
                            } else {
                                u8 prev = mem_read8_at(addr);
                                mem_write8_at(addr, (u8)(prev + (u8)aval));
                            }
                        } else if (opcode=="SUB") {
                            if (sign=='S') {
                                i8 prev = (i8)mem_read8_at(addr);
                                mem_write8_at(addr, (u8)(prev - (i8)aval));
                            } else {
                                u8 prev = mem_read8_at(addr);
                                mem_write8_at(addr, (u8)(prev - (u8)aval));
                            }
                        } else if (opcode=="MUL") {
                            if (sign=='S') {
                                i8 prev=(i8)mem_read8_at(addr);
                                mem_write8_at(addr, (u8)(prev * (i8)aval));
                            } else {
                                u8 prev=mem_read8_at(addr);
                                mem_write8_at(addr, (u8)(prev * (u8)aval));
                            }
                        } else if (opcode=="DIV") {
                            if (aval==0) throw runtime_error("division by zero");
                            if (sign=='S') {
                                i8 prev=(i8)mem_read8_at(addr);
                                mem_write8_at(addr, (u8)(prev / (i8)aval));
                            } else {
                                u8 prev=mem_read8_at(addr);
                                mem_write8_at(addr, (u8)(prev / (u8)aval));
                            }
                        } else throw runtime_error("unknown opcode "+opcode);
                    } else {
                        throw runtime_error("B must be r8N or memory for 8-bit op: "+B);
                    }
                } else if (size=='H') {
                    // 16-bit ops
                    int aval=0;
                    if (is_r16(A)) aval = (int)regs16[stoi(A.substr(3))];
                    else if (is_number(A)) aval = parse_int(A) & 0xFFFF;
                    else if (is_mem(A)) aval = mem_read16_at(resolve_address(A));
                    else throw runtime_error("unsupported A for 16-bit op: "+A);

                    if (is_r16(B)) {
                        int bi = stoi(B.substr(3));
                        int bval = regs16[bi];
                        if (opcode=="ADD") {
                            if (sign=='S') regs16[bi] = (u16)((i16)bval + (i16)aval);
                            else regs16[bi] = (u16)((u16)bval + (u16)aval);
                        } else if (opcode=="SUB") {
                            if (sign=='S') regs16[bi] = (u16)((i16)bval - (i16)aval);
                            else regs16[bi] = (u16)((u16)bval - (u16)aval);
                        } else if (opcode=="MUL") {
                            if (sign=='S') regs16[bi] = (u16)((i16)bval * (i16)aval);
                            else regs16[bi] = (u16)((u16)bval * (u16)aval);
                        } else if (opcode=="DIV") {
                            if (aval==0) throw runtime_error("division by zero");
                            if (sign=='S') regs16[bi] = (u16)((i16)bval / (i16)aval);
                            else regs16[bi] = (u16)((u16)bval / (u16)aval);
                        } else throw runtime_error("unknown opcode "+opcode);
                    } else if (is_mem(B)) {
                        u32 addr = resolve_address(B);
                        if (opcode=="ADD") {
                            if (sign=='S') mem_write16_at(addr, (u16)((i16)mem_read16_at(addr) + (i16)aval));
                            else mem_write16_at(addr, (u16)((u16)mem_read16_at(addr) + (u16)aval));
                        } else if (opcode=="SUB") {
                            if (sign=='S') mem_write16_at(addr, (u16)((i16)mem_read16_at(addr) - (i16)aval));
                            else mem_write16_at(addr, (u16)((u16)mem_read16_at(addr) - (u16)aval));
                        } else if (opcode=="MUL") {
                            if (sign=='S') mem_write16_at(addr, (u16)((i16)mem_read16_at(addr) * (i16)aval));
                            else mem_write16_at(addr, (u16)((u16)mem_read16_at(addr) * (u16)aval));
                        } else if (opcode=="DIV") {
                            if (aval==0) throw runtime_error("division by zero");
                            if (sign=='S') mem_write16_at(addr, (u16)((i16)mem_read16_at(addr) / (i16)aval));
                            else mem_write16_at(addr, (u16)((u16)mem_read16_at(addr) / (u16)aval));
                        } else throw runtime_error("unknown opcode "+opcode);
                    } else {
                        throw runtime_error("B must be r16N or memory for 16-bit op: "+B);
                    }
                } else {
                    throw runtime_error("unknown size prefix in opcode: "+op);
                }
                continue;
            }

            // Bitwise ops formats: <FlagOp> A B
// Flag prefix: size (L/H), e.g., "LAND" = 8-bit AND, "HSHL" = 16-bit SHL
if ((op.size() >= 3) && (op.find("AND") != string::npos || op.find("OR") != string::npos ||
                          op.find("XOR") != string::npos || op.find("NOT") != string::npos ||
                          op.find("SHL") != string::npos || op.find("SHR") != string::npos)) {
    char size = op[0]; // 'L' or 'H'
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
        int aval = is_r8(A) ? regs8[stoi(A.substr(2))] : parse_int(A) & 0xFF;
        if (opcode != "NOT") {
            if (is_r8(B)) {
                int bi = stoi(B.substr(2));
                int bval = regs8[bi];
                if (opcode=="AND") regs8[bi] = (u8)(bval & aval);
                else if (opcode=="OR") regs8[bi] = (u8)(bval | aval);
                else if (opcode=="XOR") regs8[bi] = (u8)(bval ^ aval);
                else if (opcode=="SHL") regs8[bi] = (u8)(bval << aval);
                else if (opcode=="SHR") regs8[bi] = (u8)(bval >> aval);
            } else if (is_mem(B)) {
                u32 addr = resolve_address(B);
                u8 bval = mem_read8_at(addr);
                if (opcode=="AND") mem_write8_at(addr, (u8)(bval & aval));
                else if (opcode=="OR") mem_write8_at(addr, (u8)(bval | aval));
                else if (opcode=="XOR") mem_write8_at(addr, (u8)(bval ^ aval));
                else if (opcode=="SHL") mem_write8_at(addr, (u8)(bval << aval));
                else if (opcode=="SHR") mem_write8_at(addr, (u8)(bval >> aval));
            } else throw runtime_error("B must be r8N or memory for L-bit bitwise op");
        } else { // NOT only uses one operand
            if (is_r8(A)) {
                int ai = stoi(A.substr(2));
                regs8[ai] = ~regs8[ai];
            } else if (is_mem(A)) {
                u32 addr = resolve_address(A);
                mem_write8_at(addr, ~mem_read8_at(addr));
            } else throw runtime_error("unsupported operand for L-bit NOT");
        }
    } else if (size == 'H') {
        int aval = is_r16(A) ? regs16[stoi(A.substr(3))] : parse_int(A) & 0xFFFF;
        if (opcode != "NOT") {
            if (is_r16(B)) {
                int bi = stoi(B.substr(3));
                int bval = regs16[bi];
                if (opcode=="AND") regs16[bi] = (u16)(bval & aval);
                else if (opcode=="OR") regs16[bi] = (u16)(bval | aval);
                else if (opcode=="XOR") regs16[bi] = (u16)(bval ^ aval);
                else if (opcode=="SHL") regs16[bi] = (u16)(bval << aval);
                else if (opcode=="SHR") regs16[bi] = (u16)(bval >> aval);
            } else if (is_mem(B)) {
                u32 addr = resolve_address(B);
                u16 bval = mem_read16_at(addr);
                if (opcode=="AND") mem_write16_at(addr, (u16)(bval & aval));
                else if (opcode=="OR") mem_write16_at(addr, (u16)(bval | aval));
                else if (opcode=="XOR") mem_write16_at(addr, (u16)(bval ^ aval));
                else if (opcode=="SHL") mem_write16_at(addr, (u16)(bval << aval));
                else if (opcode=="SHR") mem_write16_at(addr, (u16)(bval >> aval));
            } else throw runtime_error("B must be r16N or memory for H-bit bitwise op");
        } else { // NOT only
            if (is_r16(A)) {
                int ai = stoi(A.substr(3));
                regs16[ai] = ~regs16[ai];
            } else if (is_mem(A)) {
                u32 addr = resolve_address(A);
                mem_write16_at(addr, ~mem_read16_at(addr));
            } else throw runtime_error("unsupported operand for H-bit NOT");
        }
    } else throw runtime_error("unknown size prefix in bitwise opcode: " + op);

    continue;
}

            // Memory and register ops:
            // LWSB A B -> write single byte A to address B (address token can be 8 or 16 bit depending on L/H)
            // HWSB A B -> write single byte A to 16-bit address B
            // HWSW A B -> write 16-bit value A to address B (16-bit write)
            // LPUT A B -> write 8-bit value A to register r8N (B)
            // LREAD A B -> read from address A (8-bit/16-bit addressing depends on L/H) into r8N B
            // HREAD -> read into r8N from 16-bit address
            if (op=="LWSB" || op=="HWSB") {
                if (toks.size()<3) throw runtime_error("LWSB/HWSB needs 2 args");
                string A = toks[1], B = toks[2];
                int aval=0;
                if (is_r8(A)) aval = regs8[stoi(A.substr(2))];
                else if (is_number(A)) aval = parse_int(A) & 0xFF;
                else throw runtime_error("unsupported A for WSB: "+A);
                u32 addr;
                if (is_mem(B)) addr = resolve_address(B);
                else if (is_number(B)) addr = parse_int(B);
                else throw runtime_error("unsupported B address token: "+B);
                // check 8-bit addressing constraint
                if (op=="LWSB") {
                    // restrict to ram8 region
                    if (addr < ram8_offset || addr >= ram8_offset + ram8_size) {
                        throw runtime_error("LWSB 8-bit addressing allowed only within 8-bit RAM region");
                    }
                }
                mem_write8_at(addr, (u8)aval);
                continue;
            }
            if (op=="HWSW") { // write 16-bit value to memory at 16-bit address
                if (toks.size()<3) throw runtime_error("HWSW needs 2 args");
                string A=toks[1], B=toks[2];
                int aval=0;
                if (is_r16(A)) aval = regs16[stoi(A.substr(3))];
                else if (is_number(A)) aval = parse_int(A) & 0xFFFF;
                else throw runtime_error("unsupported A for HWSW: "+A);
                u32 addr;
                if (is_mem(B)) addr = resolve_address(B);
                else if (is_number(B)) addr = parse_int(B);
                else throw runtime_error("unsupported B for HWSW: "+B);
                mem_write16_at(addr, (u16)aval);
                continue;
            }
            if (op=="LPUT") {
                if (toks.size()<3) throw runtime_error("LPUT needs 2 args");
                string A=toks[1], B=toks[2];
                int aval=0;
                if (is_number(A)) aval = parse_int(A) & 0xFF;
                else if (is_r8(A)) aval = regs8[stoi(A.substr(2))];
                else throw runtime_error("unsupported A for LPUT: "+A);
                if (!is_r8(B)) throw runtime_error("LPUT B must be r8N");
                int bi = stoi(B.substr(2));
                regs8[bi] = (u8)aval;
                continue;
            }
            if (op=="LREAD" || op=="HREAD") {
                if (toks.size()<3) throw runtime_error("LREAD/HREAD needs 2 args");
                string A=toks[1], B=toks[2];
                u32 addr;
                if (is_mem(A)) addr = resolve_address(A);
                else if (is_number(A)) addr = parse_int(A);
                else throw runtime_error("unsupported A for READ: "+A);
                if (op=="LREAD") {
                    if (addr < ram8_offset || addr >= ram8_offset + ram8_size) {
                        throw runtime_error("LREAD address must be within 8-bit RAM region");
                    }
                }
                u8 val = mem_read8_at(addr);
                if (!is_r8(B)) throw runtime_error("LREAD target must be r8N");
                int bi = stoi(B.substr(2));
                regs8[bi] = val;
                continue;
            }

            // show registers / debug instruction:
            if (op=="DUMP") {
                if (toks.size()==1 || toks[1]=="REGS") {
                    cout << "r8: ";
                    for (int i=0;i<8;i++) {
                        cout << "r8_"<<i<<'='<<(int)regs8[i]<<" ";
                    }
                    cout << "\nr16: ";
                    for (int i=0;i<8;i++) {
                        cout << "r16_"<<i<<'='<<(int)regs16[i]<<" ";
                    }
                    cout << "\n";
                } else if (toks[1]=="MEM") {
                    int start = 0, len=64;
                    if (toks.size()>=4) { start = parse_int(toks[2]); len = parse_int(toks[3]); }
                    for (int i=0;i<len;i++){
                        if (i%16==0) cout << hex << setw(4) << setfill('0') << (start+i) << ": ";
                        cout << hex << setw(2) << (int)mem_read8_at(start+i) << " ";
                        if (i%16==15) cout << "\n";
                    }
                    cout << dec << "\n";
                }
                continue;
            }

            if (op == "LCMP" || op == "HCMP") {
              if (toks.size() < 3) throw runtime_error("CMP needs 2 args");
              string A = toks[1], B = toks[2];
              int aval = 0, bval = 0;

              if (op[0] == 'L') { // 8-bit
              aval = is_r8(A) ? regs8[stoi(A.substr(2))] : parse_int(A) & 0xFF;
              bval = is_r8(B) ? regs8[stoi(B.substr(2))] : mem_read8_at(resolve_address(B));
        } else {
              aval = is_r16(A) ? regs16[stoi(A.substr(3))] : parse_int(A) & 0xFFFF;
              bval = is_r16(B) ? regs16[stoi(B.substr(3))] : mem_read16_at(resolve_address(B));
          }
        set_flags(aval, bval);
      continue;
  }

// Increment / Decrement shortcuts
if (op == "INC" || op == "DEC") {
    if (toks.size() < 2) throw runtime_error(op + " needs 1 argument");
    string A = toks[1];

    if (is_r8(A)) {
        int idx = stoi(A.substr(2));
        if (op == "INC") regs8[idx] = (u8)(regs8[idx] + 1);
        else regs8[idx] = (u8)(regs8[idx] - 1);
    }
    else if (is_r16(A)) {
        int idx = stoi(A.substr(3));
        if (op == "INC") regs16[idx] = (u16)(regs16[idx] + 1);
        else regs16[idx] = (u16)(regs16[idx] - 1);
    }
    else if (A.front() == '[' && A.back() == ']') {   // <-- memory
        int addr = stoi(A.substr(1, A.size() - 2));
        if (op == "INC") mem[addr] += 1;
        else mem[addr] -= 1;
    }
    else throw runtime_error(op + " operand must be r8N, r16N, or [addr]");

    continue;
}

if (op == "NEG") {
    if (toks.size() < 2) throw runtime_error("NEG needs 1 argument");
    string A = toks[1];
    A.erase(0, A.find_first_not_of(" \t\r\n")); // left trim
    A.erase(A.find_last_not_of(" \t\r\n") + 1); // right trim

    if (is_r8(A)) {
        int idx = stoi(A.substr(2));
        regs8[idx] = (u8)(-regs8[idx]); // wrap in u8
    }
    else if (is_r16(A)) {
        int idx = stoi(A.substr(3));
        regs16[idx] = (u16)(-regs16[idx]); // wrap in u16
    }
    else if (A.front() == '[' && A.back() == ']') {
        // parse address and negate memory
        int addr = stoi(A.substr(1, A.size() - 2));
        mem[addr] = (u8)(-mem[addr]);
    }
    else throw runtime_error("NEG operand must be r8N, r16N, or [addr]");

    continue;
}

if (op == "DREAD") {
    if (toks.size() < 3) throw runtime_error("DREAD needs 2 arguments: sector and r8 target");
    u16 sector = stoi(toks[1]);
    u8 r = stoi(toks[2].substr(2));

    // Open disk if not already open
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
    u16 sector = stoi(toks[1]);
    u8 r = stoi(toks[2].substr(2));

    // Open disk if not already open
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
    pc = labels[lbl] + 1;
    continue;
}

if (op == "JE" || op == "JZ") {
    if (toks.size() < 2) throw runtime_error("JE/JZ needs a label");
    if (ZF) {
        string lbl = toks[1];
        if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
        pc = labels[lbl] + 1;
    }
    continue;
}

if (op == "JNE" || op == "JNZ") {
    if (toks.size() < 2) throw runtime_error("JNE/JNZ needs a label");
    if (!ZF) {
        string lbl = toks[1];
        if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
        pc = labels[lbl] + 1;
    }
    continue;
}

if (op == "JL") {
    if (toks.size() < 2) throw runtime_error("JL needs a label");
    if (SF) {
        string lbl = toks[1];
        if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
        pc = labels[lbl] + 1;
    }
    continue;
}

if (op == "JG") {
    if (toks.size() < 2) throw runtime_error("JG needs a label");
    if (!SF && !ZF) {
        string lbl = toks[1];
        if (!labels.count(lbl)) throw runtime_error("unknown label: " + lbl);
        pc = labels[lbl] + 1;
    }
    continue;
}

if (op == "PRINT") {
    if (toks.size() < 2) throw runtime_error("PRINT needs 1 argument");

    string arg = toks[1];

    if (is_r8(arg)) {
        int idx = stoi(arg.substr(2));
        cout << arg << " = " << (int)regs8[idx] << "\n";
    } 
    else if (is_r16(arg)) {
        int idx = stoi(arg.substr(3));
        cout << arg << " = " << regs16[idx] << "\n";
    } 
    else if (arg.front() == '[' && arg.back() == ']') {
        u32 addr = resolve_address(arg);
        cout << arg << " = " << (int)mem_read8_at(addr) << "\n";
    } 
    else if (is_number(arg)) {
        cout << arg << " = " << parse_int(arg) << "\n";
    } 
    else {
        throw runtime_error("unsupported PRINT argument: " + arg);
    }

    continue;
}

// PUSH A -> push 8-bit or 16-bit value onto stack
if (op == "PUSH") {
    if (toks.size() < 2) throw runtime_error("PUSH needs 1 argument");
    string A = toks[1];
    int val = 0;
    bool is16 = false;

    if (is_r8(A)) val = regs8[stoi(A.substr(2))];
    else if (is_r16(A)) { val = regs16[stoi(A.substr(3))]; is16 = true; }
    else if (is_number(A)) val = parse_int(A);
    else throw runtime_error("unsupported PUSH operand: " + A);

    if (is16) {
        if (SP < stack_base + 2) throw runtime_error("stack overflow");
        SP -= 2;
        mem_write16_at(SP, (u16)val);
    } else {
        if (SP < stack_base + 1) throw runtime_error("stack overflow");
        SP -= 1;
        mem_write8_at(SP, (u8)val);
    }
    continue;
}

// POP B -> pop value from stack into register
if (op == "POP") {
    if (toks.size() < 2) throw runtime_error("POP needs 1 argument");
    string B = toks[1];

    if (is_r8(B)) {
        if (SP >= stack_base + stack_size) throw runtime_error("stack underflow");
        regs8[stoi(B.substr(2))] = mem_read8_at(SP);
        SP += 1;
    } else if (is_r16(B)) {
        if (SP + 1 >= stack_base + stack_size) throw runtime_error("stack underflow");
        regs16[stoi(B.substr(3))] = mem_read16_at(SP);
        SP += 2;
    } else throw runtime_error("unsupported POP target: " + B);

    continue;
}
            throw runtime_error("unknown instruction: " + op);
        }
    }
};

int main() {
    try {
        CPU cpu(65536, 8192, 256);

        // Precompute RAM8 base address
        int ram8_base = cpu.mem_size - cpu.ram8_size;

        // Program with proper arithmetic so r81 gets a non-zero value
        vector<string> prog = {
    "DREAD 2 r80",
    "PRINT r80",
    "DWRITE 3 r80",
    "PRINT r80",
    "DREAD 3 r81",
    "PRINT r81",
    "LWSB r81 [65280]",
    "QUIT"
};
        cpu.load_program_lines(prog);
        cpu.run();

        // Dump 8-bit RAM heheh
        std::cout << "Executing instruction: LWSB r81 [" << ram8_base << "]\n";
        std::cout << "Dumping 8-bit RAM region:\n";
        for (int i = 0; i < cpu.ram8_size; i++) {
            if (i % 16 == 0) cout << hex << setw(4) << setfill('0') << (ram8_base + i) << ": ";
            cout << hex << setw(2) << setfill('0') << (int)cpu.mem[ram8_base + i] << " ";
            if (i % 16 == 15) cout << "\n";
        }
        cout << dec << "\n";

    } catch (const std::exception &ex) {
        cerr << "Runtime error: " << ex.what() << "\n";
        return 2;
    }
    return 0;
}