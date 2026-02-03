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
    // statics
    static const u32 PAGE_SIZE = 256;
    static const u32 PAGE_MASK = 0xFF;
    static const u32 PAGE_SHIFT = 8;
    static const u32 TOTAL_PAGES = 256;
    static const u32 MAX_PORTS = 65536;
    static const int TLB_SIZE = 16;

    // registers
    array<u8, 32> regs8{};
    array<u8, 256> interrupt_priorities{};
    array<u8, 256> interrupt_privilege_levels{};
    array<u8, MAX_PORTS> io_ports{};
    array<u8, 8192> io_permission_bitmap{};
    array<u16, 32> regs16{};
    array<float, 32> regs_f32{};
    array<double, 32> regs_f64{};
    array<bool, TOTAL_PAGES> physical_pages_used;
    array<u32, 256> interrupt_vector_table{};
    queue<pair<u8, u8>> pending_interrupts;
    u8 current_priority = 0;
    u8 current_privilege_level = 0;
    u8 page_fault_error_code = 0;
    u8 io_privilege_level = 0;
    u32 SP = 0; 
    u32 timer_counter = 0;
    u32 timer_interval = 0;
    u32 page_directory_base = 0;
    u32 page_fault_address = 0;
    u32 hardware_cycle_counter = 0;
    int interrupt_depth = 0;
    
    // memory
    vector<u8> mem;
    size_t mem_size = 65536;
    size_t stack_base = 0;
    size_t stack_size = 1024;

    // flags
    bool interrupt_enabled = true;
    bool trap_flag = false;
    bool timer_enabled = false;
    bool in_interrupt_handler = false;
    bool supervisor_mode = true;
    bool paging_enabled = false;
    bool io_bitmap_enabled = false;
    bool ZF = false;  // Zero Flag
    bool SF = false;  // Sign Flag
    bool CF = false;  // Carry Flag
    bool OF = false;  // Overflow Flag
    bool FZ = false;
    bool FN = false;
    bool FE = false;
    bool FG = false;
    bool FL = false;

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

    struct MemorySegment {
        u32 base;
        u32 limit;
        u8 privilege_level;
        bool writable;
        bool executable;
    };

    struct PageTableEntry {
        u32 physical_page : 24;
        u8 present : 1;
        u8 writable : 1;
        u8 user : 1;
        u8 accessed : 1;
        u8 dirty : 1;
        u8 reserved : 3;
    };

    struct PageDirectoryEntry {
        u32 page_table_addr : 24;
        u8 present : 1;
        u8 writable : 1;
        u8 user : 1;
        u8 accessed : 1;
        u8 reserved : 4;
    };

    struct TLBEntry {
        u32 virtual_page;
        u32 physical_page;
        bool present;
        bool writable;
        bool user;
        bool valid;
    };

    struct Process {
        u32 page_directory;
        u8 privilege_level;
        u32 base_address;
        u32 size;
        bool active;
        string name;
    };

    struct HardwareDevice {
        bool enabled = false;
        u8 interrupt_number = 0;
        u32 cycles_until_interrupt = 0;
        u32 interrupt_interval = 0;  // 0 = one-shot, >0 = periodic
        bool interrupt_pending = false;
        string name;
    };

    struct SerialPortHW {
        queue<u8> tx_buffer;
        queue<u8> rx_buffer;
        bool tx_interrupt_enabled = false;
        bool rx_interrupt_enabled = false;
        u8 interrupt_number = 0;
        u32 baud_delay = 100;  // Cycles per byte
        u32 cycles_until_tx_ready = 0;
        u32 cycles_until_rx_ready = 0;
        u8 pending_rx_byte = 0;
        bool has_pending_rx = false;
    };

    struct KeyboardHW {
        queue<u8> scancode_queue;
        bool interrupt_enabled = true;
        u8 interrupt_number = 1;  // IRQ1
        u32 typematic_delay = 500;  // Cycles between key repeats
        u32 cycles_until_next_key = 0;
        u8 last_scancode = 0;
    };

    struct PITHW {
        bool interrupt_enabled = true;
        u8 interrupt_number = 0;  // IRQ0
        u32 reload_value = 1193;  // ~1ms at 1.193 MHz
        u32 current_count = 0;
        bool counting = true;
    };

    struct DiskHW {
        bool interrupt_enabled = true;
        u8 interrupt_number = 14;  // IRQ14 (primary IDE)
        bool operation_pending = false;
        u32 cycles_until_complete = 0;
        u32 operation_delay = 1000;  // Cycles for disk operation
        u8 last_status = 0x50;  // DRDY | DSC
    };

    struct MouseHW {
        bool interrupt_enabled = false;
        u8 interrupt_number = 12;  // IRQ12
        queue<u8> movement_queue;
        u32 cycles_until_movement = 0;
        i8 delta_x = 0;
        i8 delta_y = 0;
        u8 buttons = 0;
    };

    struct RTCHW {
        bool interrupt_enabled = false;
        u8 interrupt_number = 8;  // IRQ8
        u32 periodic_interval = 1024;  // Cycles
        u32 cycles_until_tick = 0;
        u8 seconds = 0;
        u8 minutes = 0;
        u8 hours = 0;
    };

    RTCHW rtc_hw;
    MouseHW mouse_hw;
    DiskHW disk_hw;
    PITHW pit_hw;
    KeyboardHW keyboard_hw;
    array<Process, 8> processes;
    array<TLBEntry, TLB_SIZE> tlb;
    array<MemorySegment, 8> segments;
    array<HardwareDevice, 16> hardware_devices;  // Up to 16 hardware devices
    array<SerialPortHW, 4> serial_hw;
    u8 current_code_segment = 0;
    u8 current_process = 0;
    u8 current_data_segment = 0;
    bool protection_enabled = 0;
    int tlb_next = 0;
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
        if (protection_enabled &&
            current_privilege_level > interrupt_privilege_levels[interrupt_num]) {
                throw runtime_error("Privilege violation: cannot trigger interrupt " +
                                    to_string(interrupt_num) + " from CPL " +
                                    to_string(current_privilege_level));
            }

        u8 priority = interrupt_priorities[interrupt_num];
        pending_interrupts.push(std::make_pair(interrupt_num, priority));
    }

    void check_memory_access(u32 addr, bool is_write) {
        if (!protection_enabled) return;
    
        // Check if address is in current data segment
        MemorySegment& seg = segments[current_data_segment];
    
        if (addr < seg.base || addr >= seg.base + seg.limit) {
            throw runtime_error("Segment violation: address " + to_string(addr) + 
                            " outside segment bounds");
        }
    
        if (is_write && !seg.writable) {
            throw runtime_error("Write protection violation: segment is read-only");
        }
        
        if (current_privilege_level > seg.privilege_level) {
            throw runtime_error("Privilege violation: CPL=" + to_string(current_privilege_level) +
                              " > segment DPL=" + to_string(seg.privilege_level));
        }
    }

    u32 allocate_physical_page() {
        for (u32 i = 0; i < TOTAL_PAGES; i++) {
            if (!physical_pages_used[i]) {
                physical_pages_used[i] = true;
                return i;
            }
        }
        throw runtime_error("out of physical memory");
    }

    void free_physical_page(u32 page_num) {
        if (page_num < TOTAL_PAGES) {
            physical_pages_used[page_num] = false;
        }
    }

    void tlb_flush() {
        for (auto& entry : tlb) {
            entry.valid = false;
        }
    }

    void tlb_flush_page(u32 virtual_page) {
        for (auto& entry : tlb) {
            if (entry.valid && entry.virtual_page == virtual_page) {
                entry.valid = false;
            }
        }
    }

    void tlb_insert(u32 virtual_page, u32 physical_page, bool writable, bool user) {
        tlb[tlb_next].virtual_page = virtual_page;
        tlb[tlb_next].physical_page = physical_page;
        tlb[tlb_next].writable = writable;
        tlb[tlb_next].user = user;
        tlb[tlb_next].present = true;
        tlb[tlb_next].valid = true;

        tlb_next = (tlb_next + 1) % TLB_SIZE;
    }

    TLBEntry* tlb_lookup(u32 virtual_page) {
        for (auto& entry : tlb) {
            if (entry.valid && entry.virtual_page == virtual_page) {
                return &entry;
            }
        }
        return nullptr;
    }

    // Update the translate_address function:
    u32 translate_address(u32 virtual_addr, bool is_write, bool& writable, bool& user_accessible) {
        if (!paging_enabled) {
            writable = true;
            user_accessible = true;
            return virtual_addr;
        }
        
        u32 virtual_page = virtual_addr >> PAGE_SHIFT;
        u32 offset = virtual_addr & PAGE_MASK;
        
        // Check TLB first
        TLBEntry* tlb_entry = tlb_lookup(virtual_page);
        if (tlb_entry) {
            writable = tlb_entry->writable;
            user_accessible = tlb_entry->user;
            
            // Check permissions
            if (is_write && !writable) {
                page_fault_address = virtual_addr;
                page_fault_error_code = 0x02;
                throw runtime_error("Page fault: write to read-only page at " + to_string(virtual_addr));
            }
            
            if (!user_accessible && current_privilege_level == 3) {
                page_fault_address = virtual_addr;
                page_fault_error_code = 0x04;
                throw runtime_error("Page fault: user access to supervisor page at " + to_string(virtual_addr));
            }
            
            return (tlb_entry->physical_page << PAGE_SHIFT) | offset;
        }
        
        // TLB miss - walk page table (single level)
        // Each page table entry is 4 bytes
        u32 pte_addr = page_directory_base + virtual_page * 4;
        
        if (pte_addr + 3 >= mem_size) {
            throw runtime_error("Page table out of bounds");
        }
        
        u32 pte_raw = mem[pte_addr] | 
                      (mem[pte_addr + 1] << 8) | 
                      (mem[pte_addr + 2] << 16) | 
                      (mem[pte_addr + 3] << 24);
        
        PageTableEntry pte;
        pte.present = pte_raw & 0x01;
        pte.writable = (pte_raw >> 1) & 0x01;
        pte.user = (pte_raw >> 2) & 0x01;
        pte.accessed = (pte_raw >> 3) & 0x01;
        pte.dirty = (pte_raw >> 4) & 0x01;
        pte.physical_page = (pte_raw >> 8) & 0xFF;
        
        if (!pte.present) {
            page_fault_address = virtual_addr;
            page_fault_error_code = 0x00;
            throw runtime_error("Page fault: page not present at " + to_string(virtual_addr));
        }
        
        // Check permissions
        bool is_writable = pte.writable;
        bool is_user = pte.user;
        
        if (is_write && !is_writable) {
            page_fault_address = virtual_addr;
            page_fault_error_code = 0x02;
            throw runtime_error("Page fault: write to read-only page at " + to_string(virtual_addr));
        }
        
        if (!is_user && current_privilege_level == 3) {
            page_fault_address = virtual_addr;
            page_fault_error_code = 0x04;
            throw runtime_error("Page fault: user access to supervisor page at " + to_string(virtual_addr));
        }
        
        // Set accessed bit (and dirty bit if writing)
        if (!pte.accessed || (is_write && !pte.dirty)) {
            pte_raw |= 0x08;  // Set accessed
            if (is_write) {
                pte_raw |= 0x10;  // Set dirty
            }
            mem[pte_addr] = pte_raw & 0xFF;
            mem[pte_addr + 1] = (pte_raw >> 8) & 0xFF;
            mem[pte_addr + 2] = (pte_raw >> 16) & 0xFF;
            mem[pte_addr + 3] = (pte_raw >> 24) & 0xFF;
        }
        
        // Insert into TLB
        tlb_insert(virtual_page, pte.physical_page, is_writable, is_user);
        
        writable = is_writable;
        user_accessible = is_user;
        
        u32 physical_addr = (pte.physical_page << PAGE_SHIFT) | offset;
        return physical_addr;
    }

    void check_io_permission(u16 port) {
        if (current_privilege_level > io_privilege_level) {
            if (io_bitmap_enabled) {
                u32 byte_index = port / 8;
                u8 bit_index = port % 8;

                if (io_permission_bitmap[byte_index] & (1 << bit_index)) {
                    throw runtime_error("I/O permission violation: port " +
                                        to_string(port) + " at CPL " +
                                        to_string(current_privilege_level));
                }
            } else {
                throw runtime_error("I/O permission violation: port " +
                                    to_string(port) + " requires CPL <= " +
                                    to_string(io_privilege_level));
            }
        }
    }

    void update_hardware_devices() {
        hardware_cycle_counter++;
    
        // ==================== PIT (Timer) ====================
        if (pit_hw.counting && pit_hw.interrupt_enabled) {
            pit_hw.current_count++;
            if (pit_hw.current_count >= pit_hw.reload_value) {
                pit_hw.current_count = 0;
                trigger_interrupt(pit_hw.interrupt_number);
            }
        }
        
        // ==================== Serial Ports ====================
        for (int i = 0; i < 4; i++) {
            SerialPortHW& serial = serial_hw[i];
            
            // Transmit ready interrupt
            if (serial.tx_interrupt_enabled && serial.cycles_until_tx_ready > 0) {
                serial.cycles_until_tx_ready--;
                if (serial.cycles_until_tx_ready == 0 && !serial.tx_buffer.empty()) {
                    // Transmit complete
                    u8 byte = serial.tx_buffer.front();
                    serial.tx_buffer.pop();
                    cout << "[COM" << (i+1) << " TX: '" << (char)byte << "' (0x" 
                         << hex << (int)byte << dec << ")]\n";
                    trigger_interrupt(serial.interrupt_number);
                }
            }
            
            // Receive ready interrupt
            if (serial.rx_interrupt_enabled && serial.has_pending_rx) {
                serial.cycles_until_rx_ready--;
                if (serial.cycles_until_rx_ready == 0) {
                    serial.rx_buffer.push(serial.pending_rx_byte);
                    serial.has_pending_rx = false;
                    cout << "[COM" << (i+1) << " RX: 0x" << hex << (int)serial.pending_rx_byte 
                         << dec << "]\n";
                    trigger_interrupt(serial.interrupt_number);
                }
            }
        }
        
        // ==================== Keyboard ====================
        if (keyboard_hw.interrupt_enabled && !keyboard_hw.scancode_queue.empty()) {
            keyboard_hw.cycles_until_next_key--;
            if (keyboard_hw.cycles_until_next_key == 0) {
                u8 scancode = keyboard_hw.scancode_queue.front();
                keyboard_hw.scancode_queue.pop();
                keyboard_hw.last_scancode = scancode;
                
                cout << "[Keyboard: scancode 0x" << hex << (int)scancode << dec << "]\n";
                trigger_interrupt(keyboard_hw.interrupt_number);
                
                // Set up next key
                if (!keyboard_hw.scancode_queue.empty()) {
                    keyboard_hw.cycles_until_next_key = keyboard_hw.typematic_delay;
                }
            }
        }
        
        // ==================== Disk Controller ====================
        if (disk_hw.operation_pending) {
            disk_hw.cycles_until_complete--;
            if (disk_hw.cycles_until_complete == 0) {
                disk_hw.operation_pending = false;
                disk_hw.last_status = 0x50;  // Ready
                
                cout << "[Disk: operation complete]\n";
                if (disk_hw.interrupt_enabled) {
                    trigger_interrupt(disk_hw.interrupt_number);
                }
            }
        }
        
        // ==================== Mouse ====================
        if (mouse_hw.interrupt_enabled && !mouse_hw.movement_queue.empty()) {
            mouse_hw.cycles_until_movement--;
            if (mouse_hw.cycles_until_movement == 0) {
                mouse_hw.movement_queue.pop();
                
                cout << "[Mouse: movement detected]\n";
                trigger_interrupt(mouse_hw.interrupt_number);
                
                if (!mouse_hw.movement_queue.empty()) {
                    mouse_hw.cycles_until_movement = 50;  // Delay between movements
                }
            }
        }
        
        // ==================== RTC ====================
            if (rtc_hw.interrupt_enabled) {
            rtc_hw.cycles_until_tick--;
            if (rtc_hw.cycles_until_tick == 0) {
                rtc_hw.cycles_until_tick = rtc_hw.periodic_interval;
                trigger_interrupt(rtc_hw.interrupt_number);
            }
        }
        
        // ==================== Generic Hardware Devices ====================
        for (auto& dev : hardware_devices) {
            if (dev.enabled && dev.cycles_until_interrupt > 0) {
                dev.cycles_until_interrupt--;
                if (dev.cycles_until_interrupt == 0) {
                    cout << "[HW Device: " << dev.name << " interrupt]\n";
                    trigger_interrupt(dev.interrupt_number);
                    
                    if (dev.interrupt_interval > 0) {
                        // Periodic interrupt
                        dev.cycles_until_interrupt = dev.interrupt_interval;
                    } else {
                        // One-shot
                        dev.enabled = false;
                    }
                }
            }
        }
    }

    void handle_interrupt(u8 interrupt_num, size_t& pc) {
        u8 priority = interrupt_priorities[interrupt_num];

            // Check if non-maskable or interrupts enabled
            if (!interrupt_enabled && priority < 16) {
                return;  // Maskable interrupts disabled
            }

            u32 handler_addr = interrupt_vector_table[interrupt_num];

            if (handler_addr == 0) {
                cout << "WARNING: No handler for interrupt " << (int)interrupt_num << "\n";
                return;
            }

            // Push current priority, flags, and return address
            if (SP < stack_base + 6) throw runtime_error("stack overflow during interrupt");

            // Push return address
            SP -= 2;
            mem_write16_at(SP, (u16)pc);
        
            // Push flags
            u16 flags = 0;
            flags |= (ZF ? (1 << 0) : 0);
            flags |= (SF ? (1 << 1) : 0);
            flags |= (CF ? (1 << 2) : 0);
            flags |= (OF ? (1 << 3) : 0);
            flags |= (interrupt_enabled ? (1 << 4) : 0);
            flags |= (trap_flag ? (1 << 5) : 0);
            SP -= 2;
            mem_write16_at(SP, flags);
            
            // Push current priority
            SP -= 1;
            mem_write8_at(SP, current_priority);
            
            // Set new priority
            u8 old_priority = current_priority;
            current_priority = priority;
            
            cout << "  [INT " << (int)interrupt_num << " @ PRI " << (int)priority 
                 << " (was " << (int)old_priority << ")]\n";
            
            // Only disable interrupts for maskable interrupts
            // NMIs and higher priority can still interrupt
            if (priority < 16) {
                interrupt_enabled = false;  // Disable only for maskable interrupts
            }
            // Note: For NMIs (priority >= 16), we leave interrupt_enabled as-is
            // This allows lower priority maskable interrupts to queue but not fire
            // while higher priority interrupts can still preempt
            
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

        current_privilege_level = 0;
        supervisor_mode = true;

        for (int i = 0; i < 256; i++) {
            interrupt_privilege_levels[i] = 0;
        }

        segments[0].base = 0;
        segments[0].limit = mem_size;
        segments[0].privilege_level = 0;
        segments[0].writable = true;
        segments[0].executable = true;

        current_code_segment = 0;
        current_data_segment = 0;
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

    u8 mem_read8_at(u32 virtual_addr) {
        bool writable, user_accessible;
        u32 physical_addr = translate_address(virtual_addr, false, writable, user_accessible);
    
        if (physical_addr >= mem_size) {
            throw runtime_error("Physical memory read8 out of bounds at " + to_string(physical_addr));
        }
        return mem[physical_addr];
    }

    void mem_write8_at(u32 virtual_addr, u8 val) {
        bool writable, user_accessible;
        u32 physical_addr = translate_address(virtual_addr, true, writable, user_accessible);
    
        if (physical_addr >= mem_size) {
            throw runtime_error("Physical memory write8 out of bounds at " + to_string(physical_addr));
        }
        mem[physical_addr] = val;
    }

    u16 mem_read16_at(u32 virtual_addr) {
        bool writable, user_accessible;
        u32 physical_addr = translate_address(virtual_addr, false, writable, user_accessible);
    
        if (physical_addr + 1 >= mem_size) {
            throw runtime_error("Physical memory read16 out of bounds at " + to_string(physical_addr));
        }
        return (u16)mem[physical_addr] | ((u16)mem[physical_addr + 1] << 8);
    }

    void mem_write16_at(u32 virtual_addr, u16 val) {
        bool writable, user_accessible;
        u32 physical_addr = translate_address(virtual_addr, true, writable, user_accessible);
    
        if (physical_addr + 1 >= mem_size) {
            throw runtime_error("Physical memory write16 out of bounds at " + to_string(physical_addr));
        }
        mem[physical_addr] = (u8)(val & 0xFF);
        mem[physical_addr + 1] = (u8)((val >> 8) & 0xFF);
    }

void run() {
    preprocess_labels();
    size_t pc = 0;
    
    while (pc < program.size()) {
        update_hardware_devices();
        // Process all pending interrupts that can fire NOW
        bool processed_interrupt = true;
        while (processed_interrupt && !pending_interrupts.empty()) {
            processed_interrupt = false;
            
            // Find highest priority pending interrupt that can fire
            u8 highest_pri = 0;
            u8 highest_int = 0;
            bool found = false;
            
            // Scan queue for highest priority interrupt
            queue<pair<u8, u8>> remaining;
            
            while (!pending_interrupts.empty()) {
                pair<u8, u8> int_pair = pending_interrupts.front();
                pending_interrupts.pop();
                
                u8 int_num = int_pair.first;
                u8 pri = int_pair.second;
                
                // Check if this interrupt can fire
                bool is_nmi = (pri >= 16);  // Priorities 16-31 are NMI
                bool can_interrupt = is_nmi || (interrupt_enabled && pri > current_priority);
                
                if (can_interrupt && (!found || pri > highest_pri)) {
                    // Found a higher priority interrupt
                    if (found) {
                        // Put previous candidate back
                        remaining.push(std::make_pair(highest_int, highest_pri));
                    }
                    highest_int = int_num;
                    highest_pri = pri;
                    found = true;
                } else {
                    // Can't fire yet, keep in queue
                    remaining.push(std::make_pair(int_num, pri));
                }
            }
            
            // Restore remaining interrupts
            pending_interrupts = remaining;
            
            // Fire the highest priority interrupt if found
            if (found) {
                handle_interrupt(highest_int, pc);
                processed_interrupt = true;  // Check again for more interrupts
            }
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
                    // Find highest priority pending interrupt
                    u8 highest_pri = 0;
                    u8 highest_int = 0;
                    bool found = false;
    
                    // Scan queue for highest priority interrupt
                    queue<pair<u8, u8>> remaining;
    
                    while (!pending_interrupts.empty()) {
                        pair<u8, u8> int_pair = pending_interrupts.front();
                        pending_interrupts.pop();
        
                        u8 int_num = int_pair.first;
                        u8 pri = int_pair.second;
                        
                        // Check if this interrupt can fire
                        bool is_nmi = (pri >= 16);  // Priorities 16-31 are NMI
                        bool can_interrupt = is_nmi || (pri > current_priority);
                        
                        if (can_interrupt && (!found || pri > highest_pri)) {
                            // Found a higher priority interrupt
                            if (found) {
                                // Put previous candidate back
                                remaining.push(std::make_pair(highest_int, highest_pri));
                            }
                            highest_int = int_num;
                            highest_pri = pri;
                            found = true;
                        } else {
                            // Can't fire yet, keep in queue
                            remaining.push(std::make_pair(int_num, pri));
                        }
                    }
                    
                    // Restore remaining interrupts
                    pending_interrupts = remaining;
                    
                    // Fire the highest priority interrupt if found
                    if (found && (interrupt_enabled || highest_pri >= 16)) {
                        handle_interrupt(highest_int, pc);
                    } else {
                        break;  // No interrupt can fire right now
                    }
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
                if (SP > stack_base + stack_size - 5) throw runtime_error("stack underflow during IRET");
    
                // Pop current priority
                u8 old_priority = mem_read8_at(SP);
                SP += 1;
    
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
    
                current_priority = old_priority;  // Restore old priority
                interrupt_depth--;
    
                cout << "  [IRET: restored priority " << (int)old_priority << "]\n";
    
                pc = ret_addr;
                continue;
            }

            if (op == "HLT") {
                // Real HLT: Stop execution until an interrupt occurs
                // Process any pending interrupt to wake from halt
                if (!pending_interrupts.empty()) {
                    pair<u8, u8> int_pair = pending_interrupts.front();
                    pending_interrupts.pop();
                    handle_interrupt(int_pair.first, pc);
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

            if  (op == "SETPRI") {
                if (toks.size() < 3) throw runtime_error("SETPRI needs 2 arguments: interrupt_number priority");
                string int_str = toks[1], pri_str = toks[2];
    
                u8 int_num = 0;
                if (is_r8(int_str)) int_num = regs8[get_r8_index(int_str)];
                else if (is_number(int_str)) int_num = (u8)parse_int(int_str);
                else throw runtime_error("SETPRI: interrupt number must be r8 or immediate");
    
                u8 priority = 0;
                if (is_r8(pri_str)) priority = regs8[get_r8_index(pri_str)];
                else if (is_number(pri_str)) priority = (u8)parse_int(pri_str);
                else throw runtime_error("SETPRI: priority must be r8 or immediate (0-31)");
    
                if (priority > 31) priority = 31;  // Clamp to max
                interrupt_priorities[int_num] = priority;
    
                cout << "Set interrupt " << (int)int_num << " priority to " << (int)priority << "\n";
                continue;
            }

            if (op == "SETCPL") {
                if (current_privilege_level != 0) {
                    throw runtime_error("SETCPL: requires kernel mode (CPL=0)");
                }
                if (toks.size() < 2) throw runtime_error("SETCPL needs 1 argument");
    
                u8 new_cpl = 0;
                if (is_r8(toks[1])) new_cpl = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) new_cpl = (u8)parse_int(toks[1]);
                else throw runtime_error("SETCPL: argument must be r8 or immediate");
                
                if (new_cpl > 3) new_cpl = 3;
                current_privilege_level = new_cpl;
                supervisor_mode = (new_cpl < 3);
                
                cout << "CPL changed to " << (int)new_cpl << " (" 
                     << (supervisor_mode ? "supervisor" : "user") << " mode)\n";
                continue;
            }

            // GETCPL - Get Current Privilege Level
            // Syntax: GETCPL dest_reg
            if (op == "GETCPL") {
                if (toks.size() < 2) throw runtime_error("GETCPL needs 1 argument");
                string dst = toks[1];
                
                if (is_r8(dst)) {
                   regs8[get_r8_index(dst)] = current_privilege_level;
                } else if (is_r16(dst)) {
                    regs16[get_r16_index(dst)] = current_privilege_level;
                } else {
                    throw runtime_error("GETCPL: destination must be register");
                }
                continue;
            }

            if (op == "SETIPL") {
                if (current_privilege_level != 0) {
                    throw runtime_error("SETIPL: requires kernel mode (CPL=0)");
                }
                if (toks.size() < 3) throw runtime_error("SETIPL needs 2 arguments");
    
                u8 int_num = 0;
                if (is_r8(toks[1])) int_num = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) int_num = (u8)parse_int(toks[1]);
                else throw runtime_error("SETIPL: interrupt number must be r8 or immediate");
    
                u8 req_priv = 0;
                if (is_r8(toks[2])) req_priv = regs8[get_r8_index(toks[2])];
                else if (is_number(toks[2])) req_priv = (u8)parse_int(toks[2]);
                else throw runtime_error("SETIPL: privilege must be r8 or immediate");
    
                if (req_priv > 3) req_priv = 3;
                interrupt_privilege_levels[int_num] = req_priv;
                
                cout << "Interrupt " << (int)int_num << " requires CPL <= " << (int)req_priv << "\n";
                continue;
            }

            if (op == "SETSEG") {
                if (current_privilege_level != 0) {
                    throw runtime_error("SETSEG: requires kernel mode (CPL=0)");
                }
                if (toks.size() < 7) throw runtime_error("SETSEG needs 6 arguments");
    
                u8 seg_num = (u8)parse_int(toks[1]);
                if (seg_num >= 8) throw runtime_error("SETSEG: segment number must be 0-7");
    
                segments[seg_num].base = parse_int(toks[2]);
                segments[seg_num].limit = parse_int(toks[3]);
                segments[seg_num].privilege_level = (u8)parse_int(toks[4]);
                segments[seg_num].writable = (parse_int(toks[5]) != 0);
                segments[seg_num].executable = (parse_int(toks[6]) != 0);
    
                cout << "Segment " << (int)seg_num << " configured: base=" << segments[seg_num].base
                     << " limit=" << segments[seg_num].limit << " DPL=" << (int)segments[seg_num].privilege_level << "\n";
                continue;
            }

            if (op == "LOADCS") {
                if (toks.size() < 2) throw runtime_error("LOADCS needs 1 argument");
    
                u8 seg_num = 0;
                if (is_r8(toks[1])) seg_num = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) seg_num = (u8)parse_int(toks[1]);
                else throw runtime_error("LOADCS: argument must be r8 or immediate");
    
                if (seg_num >= 8) throw runtime_error("LOADCS: invalid segment");
    
                // Check privilege
                u8 seg_dpl = segments[seg_num].privilege_level;
                if (seg_dpl < current_privilege_level) {
                    throw runtime_error("LOADCS: cannot increase privilege without proper gate");
                }
    
                if (!segments[seg_num].executable) {
                    throw runtime_error("LOADCS: segment is not executable");
                }
                
                current_code_segment = seg_num;
                current_privilege_level = seg_dpl;
                supervisor_mode = (seg_dpl < 3);
                
                cout << "Code segment changed to " << (int)seg_num 
                     << ", CPL now " << (int)current_privilege_level << "\n";
                continue;
            }

            if (op == "LOADDS") {
                if (toks.size() < 2) throw runtime_error("LOADDS needs 1 argument");
    
                u8 seg_num = 0;
                if (is_r8(toks[1])) seg_num = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) seg_num = (u8)parse_int(toks[1]);
                else throw runtime_error("LOADDS: argument must be r8 or immediate");
    
                if (seg_num >= 8) throw runtime_error("LOADDS: invalid segment");
    
                current_data_segment = seg_num;
                cout << "Data segment changed to " << (int)seg_num << "\n";
                continue;
            }

            if (op == "SYSCALL") {
                if (toks.size() < 2) throw runtime_error("SYSCALL needs 1 argument");
    
                u8 syscall_num = 0;
                if (is_r8(toks[1])) syscall_num = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) syscall_num = (u8)parse_int(toks[1]);
                else throw runtime_error("SYSCALL: argument must be r8 or immediate");
    
                // Save current state
                if (SP < stack_base + 6) throw runtime_error("stack overflow during syscall");
    
                SP -= 2;
                mem_write16_at(SP, (u16)pc);  // Return address
    
                SP -= 1;
                mem_write8_at(SP, current_privilege_level);  // Save CPL
                
                // Switch to kernel mode
                u8 old_cpl = current_privilege_level;
               current_privilege_level = 0;
                supervisor_mode = true;
                
                cout << "  [SYSCALL " << (int)syscall_num << ": CPL " 
                     << (int)old_cpl << " -> 0]\n";
                
                // Jump to syscall handler (stored in interrupt vector)
                if (interrupt_vector_table[syscall_num] != 0) {
                    pc = interrupt_vector_table[syscall_num];
                } else {
                    throw runtime_error("SYSCALL: no handler for syscall " + to_string(syscall_num));
                }
                
                continue;
            }

            if (op == "SYSRET") {
                if (current_privilege_level != 0) {
                    throw runtime_error("SYSRET: requires kernel mode (CPL=0)");
                }
    
                if (SP + 3 > stack_base + stack_size) throw runtime_error("stack underflow during sysret");
    
                // Restore privilege level
                u8 old_cpl = mem_read8_at(SP);
                SP += 1;
                
                // Restore return address
                u16 ret_addr = mem_read16_at(SP);
                SP += 2;
                
                current_privilege_level = old_cpl;
                supervisor_mode = (old_cpl < 3);
                
                cout << "  [SYSRET: CPL 0 -> " << (int)old_cpl << "]\n";
                
                pc = ret_addr;
                continue;
            }

            if (op == "IOPL") {
                if (toks.size() < 2) throw runtime_error("IOPL needs 1 argument");
                string dst = toks[1];
    
                u8 result = (current_privilege_level <= 1) ? 1 : 0;  // I/O requires CPL <= 1
    
                if (is_r8(dst)) {
                    regs8[get_r8_index(dst)] = result;
                } else {
                    throw runtime_error("IOPL: destination must be r8");
                }
                continue;
            }

            if (op == "ENABLEPAGING") {
                if (current_privilege_level != 0) {
                    throw runtime_error("ENABLEPAGING: requires kernel mode");
                }
                if (toks.size() < 2) throw runtime_error("ENABLEPAGING needs 1 argument");
                
                u32 pd_addr = 0;
                if (is_r16(toks[1])) pd_addr = regs16[get_r16_index(toks[1])];
                else if (is_r8(toks[1])) pd_addr = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) pd_addr = parse_int(toks[1]);
                else throw runtime_error("ENABLEPAGING: address must be register or immediate");
                
                page_directory_base = pd_addr;
                paging_enabled = true;
                tlb_flush();
                
                cout << "Paging enabled with directory at 0x" << hex << pd_addr << dec << "\n";
                continue;
            }

            if (op == "DISABLEPAGING") {
                if (current_privilege_level != 0) {
                    throw runtime_error("DISABLEPAGING: requires kernel mode");
                }
                
                paging_enabled = false;
                page_directory_base = 0;
                tlb_flush();
                
                cout << "Paging disabled\n";
                continue;
            }

            if (op == "SETPD") {
                if (current_privilege_level != 0) {
                    throw runtime_error("SETPD: requires kernel mode");
                }
                if (toks.size() < 2) throw runtime_error("SETPD needs 1 argument");
    
                u32 pd_addr = 0;
                if (is_r16(toks[1])) pd_addr = regs16[get_r16_index(toks[1])];
                else if (is_r8(toks[1])) pd_addr = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) pd_addr = parse_int(toks[1]);
                else throw runtime_error("SETPD: address must be register or immediate");
    
                page_directory_base = pd_addr;
                tlb_flush();
    
                cout << "Page directory base set to 0x" << hex << pd_addr << dec << "\n";
                continue;
            }

            if (op == "INVLPG") {
                if (current_privilege_level != 0) {
                    throw runtime_error("INVLPG: requires kernel mode");
                }
                if (toks.size() < 2) throw runtime_error("INVLPG needs 1 argument");
    
                u32 vaddr = 0;
                if (is_r16(toks[1])) vaddr = regs16[get_r16_index(toks[1])];
                else if (is_r8(toks[1])) vaddr = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) vaddr = parse_int(toks[1]);
                else throw runtime_error("INVLPG: address must be register or immediate");
    
                u32 vpage = vaddr >> PAGE_SHIFT;
                tlb_flush_page(vpage);
    
                continue;
            }

// MAPPG - Map a virtual page to physical page (kernel only)
            // Syntax: MAPPG virtual_page physical_page flags
            // flags: bit 0=present, bit 1=writable, bit 2=user
            if (op == "MAPPG") {
                if (current_privilege_level != 0) {
                    throw runtime_error("MAPPG: requires kernel mode");
                }
                if (toks.size() < 4) throw runtime_error("MAPPG needs 3 arguments");
    
                // Get virtual page number
                u32 vpage = 0;
                if (is_r8(toks[1])) vpage = regs8[get_r8_index(toks[1])];
                else if (is_r16(toks[1])) vpage = regs16[get_r16_index(toks[1])];
                else if (is_number(toks[1])) vpage = parse_int(toks[1]);
                else throw runtime_error("MAPPG: virtual_page must be register or immediate");
    
                // Get physical page number
                u32 ppage = 0;
                if (is_r8(toks[2])) ppage = regs8[get_r8_index(toks[2])];
                else if (is_r16(toks[2])) ppage = regs16[get_r16_index(toks[2])];
                else if (is_number(toks[2])) ppage = parse_int(toks[2]);
                else throw runtime_error("MAPPG: physical_page must be register or immediate");
                
                // Get flags
                u8 flags = 0;
                if (is_r8(toks[3])) flags = regs8[get_r8_index(toks[3])];
                else if (is_number(toks[3])) flags = (u8)parse_int(toks[3]);
                else throw runtime_error("MAPPG: flags must be register or immediate");
                
                // Temporarily disable paging to access page table
                bool was_paging = paging_enabled;
                paging_enabled = false;
                
                // Single-level page table: each entry is 4 bytes
                u32 pte_addr = page_directory_base + vpage * 4;
                
                if (pte_addr + 3 >= mem_size) {
                    throw runtime_error("Page table entry out of bounds");
                }
                
                // Write page table entry
                u32 pte_raw = (ppage << 8) | flags;
                mem[pte_addr] = pte_raw & 0xFF;
                mem[pte_addr + 1] = (pte_raw >> 8) & 0xFF;
                mem[pte_addr + 2] = (pte_raw >> 16) & 0xFF;
                mem[pte_addr + 3] = (pte_raw >> 24) & 0xFF;
                
                paging_enabled = was_paging;
                tlb_flush_page(vpage);
                
                cout << "Mapped virtual page " << vpage << " -> physical page " << ppage 
                     << " (flags=" << (int)flags << ")\n";
                continue;
            }

            // UNMAPPG - Unmap a virtual page
            if (op == "UNMAPPG") {
                if (current_privilege_level != 0) {
                    throw runtime_error("UNMAPPG: requires kernel mode");
                }
                if (toks.size() < 2) throw runtime_error("UNMAPPG needs 1 argument");
                
                u32 vpage = 0;
                if (is_r8(toks[1])) vpage = regs8[get_r8_index(toks[1])];
                else if (is_r16(toks[1])) vpage = regs16[get_r16_index(toks[1])];
                else if (is_number(toks[1])) vpage = parse_int(toks[1]);
                else throw runtime_error("UNMAPPG: virtual_page must be register or immediate");
                
                bool was_paging = paging_enabled;
                paging_enabled = false;
                
                u32 pte_addr = page_directory_base + vpage * 4;
                
                if (pte_addr + 3 < mem_size) {
                    // Clear the PTE (mark as not present)
                    mem[pte_addr] = 0;
                    mem[pte_addr + 1] = 0;
                    mem[pte_addr + 2] = 0;
                    mem[pte_addr + 3] = 0;
                }
                
                paging_enabled = was_paging;
                tlb_flush_page(vpage);
                
                cout << "Unmapped virtual page " << vpage << "\n";
                continue;
            }
            
            // CREATEPROC - Create a new process with isolated address space
            // Syntax: CREATEPROC process_id name
            if (op == "CREATEPROC") {
                if (current_privilege_level != 0) {
                    throw runtime_error("CREATEPROC: requires kernel mode");
                }
                if (toks.size() < 3) throw runtime_error("CREATEPROC needs 2 arguments");
                
                u8 pid = 0;
                if (is_r8(toks[1])) pid = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) pid = (u8)parse_int(toks[1]);
                else throw runtime_error("CREATEPROC: process_id must be register or immediate");
    
                if (pid >= 8) throw runtime_error("CREATEPROC: invalid process ID");
                
                // Allocate page table (256 entries * 4 bytes = 1024 bytes = 4 pages)
                u32 pt_page = allocate_physical_page();
                u32 pt_addr = pt_page << PAGE_SHIFT;
                
                // Allocate 3 more pages for full page table
                allocate_physical_page();
                allocate_physical_page();
                allocate_physical_page();
                
                // Clear page table
                bool was_paging = paging_enabled;
                paging_enabled = false;
                for (u32 i = 0; i < 1024; i++) {
                    mem[pt_addr + i] = 0;
                }
                paging_enabled = was_paging;
                
                processes[pid].page_directory = pt_addr;
                processes[pid].privilege_level = 3;  // User mode
                processes[pid].active = true;
                processes[pid].name = toks[2];
    
                cout << "Created process " << (int)pid << " (" << processes[pid].name 
                     << ") with page table at 0x" << hex << pt_addr << dec << "\n";
                continue;
            }
            
            // SWITCHPROC - Switch to another process
            if (op == "SWITCHPROC") {
                if (current_privilege_level != 0) {
                    throw runtime_error("SWITCHPROC: requires kernel mode");
                }
                if (toks.size() < 2) throw runtime_error("SWITCHPROC needs 1 argument");
                
                u8 pid = 0;
                if (is_r8(toks[1])) pid = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) pid = (u8)parse_int(toks[1]);
                else throw runtime_error("SWITCHPROC: process_id must be register or immediate");
                
                if (pid >= 8 || !processes[pid].active) {
                    throw runtime_error("SWITCHPROC: invalid or inactive process");
                }
                
                current_process = pid;
                page_directory_base = processes[pid].page_directory;
                tlb_flush();
                
                cout << "Switched to process " << (int)pid << " (" 
                     << processes[pid].name << ")\n";
                continue;
            }

            if (op == "IN") {
                if (toks.size() < 3) throw runtime_error("IN needs 2 arguments");
                string port_str = toks[1], dst = toks[2];
    
                u16 port = 0;
                if (is_r8(port_str)) port = regs8[get_r8_index(port_str)];
                else if (is_r16(port_str)) port = regs16[get_r16_index(port_str)];
                else if (is_number(port_str)) port = (u16)parse_int(port_str);
                else throw runtime_error("IN: port must be register or immediate");
    
                // Check permission
                check_io_permission(port);
    
                // Read from port
                u8 value = io_ports[port];
    
                // Store in destination
                if (is_r8(dst)) {
                    regs8[get_r8_index(dst)] = value;
                } else if (is_r16(dst)) {
                    regs16[get_r16_index(dst)] = value;
                } else {
                    throw runtime_error("IN: destination must be register");
                }
                
                cout << "IN: Read 0x" << hex << (int)value << " from port 0x" 
                     << port << dec << "\n";
                continue;
            }

            if (op == "OUT") {
                if (toks.size() < 3) throw runtime_error("OUT needs 2 arguments");
                string value_str = toks[1], port_str = toks[2];
    
                u16 port = 0;
                if (is_r8(port_str)) port = regs8[get_r8_index(port_str)];
                else if (is_r16(port_str)) port = regs16[get_r16_index(port_str)];
                else if (is_number(port_str)) port = (u16)parse_int(port_str);
                else throw runtime_error("OUT: port must be register or immediate");
    
                u8 value = 0;
                if (is_r8(value_str)) value = regs8[get_r8_index(value_str)];
                else if (is_number(value_str)) value = (u8)parse_int(value_str);
                else throw runtime_error("OUT: value must be r8 or immediate");
                
                // Check permission
                check_io_permission(port);
                
                // Write to port
                io_ports[port] = value;
                
                cout << "OUT: Wrote 0x" << hex << (int)value << " to port 0x" 
                     << port << dec << "\n";
                continue;
            }

            if (op == "INW") {
                if (toks.size() < 3) throw runtime_error("INW needs 2 arguments");
                string port_str = toks[1], dst = toks[2];
    
                u16 port = 0;
                if (is_r8(port_str)) port = regs8[get_r8_index(port_str)];
                else if (is_r16(port_str)) port = regs16[get_r16_index(port_str)];
                else if (is_number(port_str)) port = (u16)parse_int(port_str);
                else throw runtime_error("INW: port must be register or immediate");
    
                // Check permission for both bytes
                check_io_permission(port);
                check_io_permission(port + 1);
                
                // Read 16-bit value (little-endian)
                u16 value = io_ports[port] | ((u16)io_ports[port + 1] << 8);
                
                // Store in destination
                if (!is_r16(dst)) throw runtime_error("INW: destination must be r16");
                regs16[get_r16_index(dst)] = value;
                
                cout << "INW: Read 0x" << hex << value << " from port 0x" 
                     << port << dec << "\n";
                continue;
            }

            if (op == "OUTW") {
                if (toks.size() < 3) throw runtime_error("OUTW needs 2 arguments");
                string value_str = toks[1], port_str = toks[2];
    
                u16 port = 0;
                if (is_r8(port_str)) port = regs8[get_r8_index(port_str)];
                else if (is_r16(port_str)) port = regs16[get_r16_index(port_str)];
                else if (is_number(port_str)) port = (u16)parse_int(port_str);
                else throw runtime_error("OUTW: port must be register or immediate");
    
                u16 value = 0;
                if (is_r16(value_str)) value = regs16[get_r16_index(value_str)];
                else if (is_number(value_str)) value = (u16)parse_int(value_str);
                else throw runtime_error("OUTW: value must be r16 or immediate");
                
                // Check permission for both bytes
                check_io_permission(port);
                check_io_permission(port + 1);
                
                // Write 16-bit value (little-endian)
                io_ports[port] = value & 0xFF;
                io_ports[port + 1] = (value >> 8) & 0xFF;
                
                cout << "OUTW: Wrote 0x" << hex << value << " to port 0x" 
                     << port << dec << "\n";
                continue;
            }

            if (op == "SETIOPL") {
                if (current_privilege_level != 0) {
                    throw runtime_error("SETIOPL: requires kernel mode (CPL=0)");
                }
                if (toks.size() < 2) throw runtime_error("SETIOPL needs 1 argument");
    
                u8 new_iopl = 0;
                if (is_r8(toks[1])) new_iopl = regs8[get_r8_index(toks[1])];
                else if (is_number(toks[1])) new_iopl = (u8)parse_int(toks[1]);
                else throw runtime_error("SETIOPL: argument must be r8 or immediate");
                
                if (new_iopl > 3) new_iopl = 3;
                io_privilege_level = new_iopl;
                
                cout << "I/O privilege level set to " << (int)new_iopl << "\n";
                continue;
            }

            if (op == "IOALLOW") {
                if (current_privilege_level != 0) {
                    throw runtime_error("IOALLOW: requires kernel mode (CPL=0)");
                }
                if (toks.size() < 2) throw runtime_error("IOALLOW needs 1 argument");
                
                u16 port = 0;
                if (is_r8(toks[1])) port = regs8[get_r8_index(toks[1])];
                else if (is_r16(toks[1])) port = regs16[get_r16_index(toks[1])];
                else if (is_number(toks[1])) port = (u16)parse_int(toks[1]);
                else throw runtime_error("IOALLOW: port must be register or immediate");
                
                u32 byte_index = port / 8;
                u8 bit_index = port % 8;
                io_permission_bitmap[byte_index] &= ~(1 << bit_index);  // Clear bit = allow
                
                cout << "I/O port 0x" << hex << port << dec << " allowed\n";
                continue;
            }

            if (op == "IODENY") {
                if (current_privilege_level != 0) {
                    throw runtime_error("IODENY: requires kernel mode (CPL=0)");
                }
                if (toks.size() < 2) throw runtime_error("IODENY needs 1 argument");
    
                u16 port = 0;
                if (is_r8(toks[1])) port = regs8[get_r8_index(toks[1])];
                else if (is_r16(toks[1])) port = regs16[get_r16_index(toks[1])];
                else if (is_number(toks[1])) port = (u16)parse_int(toks[1]);
                else throw runtime_error("IODENY: port must be register or immediate");
    
                u32 byte_index = port / 8;
                u8 bit_index = port % 8;
                io_permission_bitmap[byte_index] |= (1 << bit_index);  // Set bit = deny
    
                cout << "I/O port 0x" << hex << port << dec << " denied\n";
                continue;
            }

            if (op == "ENABLEIOMAP") {
                if (current_privilege_level != 0) {
                    throw runtime_error("ENABLEIOMAP: requires kernel mode (CPL=0)");
                }
                io_bitmap_enabled = true;
                cout << "I/O permission bitmap enabled\n";
                continue;
            }

            if (op == "DISABLEIOMAP") {
                if (current_privilege_level != 0) {
                    throw runtime_error("DISABLEIOMAP: requires kernel mode (CPL=0)");
                }
                io_bitmap_enabled = false;
                cout << "I/O permission bitmap disabled\n";
                continue;
            }

            if (op == "HWDEV") {
                if (current_privilege_level != 0) {
                    throw runtime_error("HWDEV: requires kernel mode");
                }
                if (toks.size() < 6) throw runtime_error("HWDEV needs 5 arguments");
    
                u8 dev_id = (u8)parse_int(toks[1]);
                if (dev_id >= 16) throw runtime_error("HWDEV: device_id must be 0-15");
    
                HardwareDevice& dev = hardware_devices[dev_id];
                dev.interrupt_number = (u8)parse_int(toks[2]);
                dev.cycles_until_interrupt = parse_int(toks[3]);
                dev.interrupt_interval = parse_int(toks[4]);
                dev.name = toks[5];
                dev.enabled = true;
                
                cout << "Configured HW device " << (int)dev_id << ": " << dev.name 
                     << ", IRQ=" << (int)dev.interrupt_number << "\n";
                continue;
            }
            
            // HWDIS - Disable hardware device
            // Syntax: HWDIS device_id
            if (op == "HWDIS") {
                if (current_privilege_level != 0) {
                    throw runtime_error("HWDIS: requires kernel mode");
                }
                if (toks.size() < 2) throw runtime_error("HWDIS needs 1 argument");
                
                u8 dev_id = (u8)parse_int(toks[1]);
                if (dev_id >= 16) throw runtime_error("HWDIS: device_id must be 0-15");
                
                hardware_devices[dev_id].enabled = false;
                cout << "Disabled HW device " << (int)dev_id << "\n";
                continue;
            }
            
            // PITCFG - Configure PIT (Programmable Interval Timer)
            // Syntax: PITCFG reload_value interrupt_num
            if (op == "PITCFG") {
                if (current_privilege_level != 0) {
                    throw runtime_error("PITCFG: requires kernel mode");
                }
                if (toks.size() < 3) throw runtime_error("PITCFG needs 2 arguments");
    
                pit_hw.reload_value = parse_int(toks[1]);
                pit_hw.interrupt_number = (u8)parse_int(toks[2]);
                pit_hw.current_count = 0;
                pit_hw.counting = true;
                pit_hw.interrupt_enabled = true;
                
                cout << "PIT configured: reload=" << pit_hw.reload_value 
                     << ", IRQ=" << (int)pit_hw.interrupt_number << "\n";
                continue;
            }
            
            // PITSTOP - Stop PIT
            if (op == "PITSTOP") {
                if (current_privilege_level != 0) {
                    throw runtime_error("PITSTOP: requires kernel mode");
                }
                pit_hw.counting = false;
                cout << "PIT stopped\n";
                continue;
            }
            
            // PITSTART - Start PIT
            if (op == "PITSTART") {
                if (current_privilege_level != 0) {
                    throw runtime_error("PITSTART: requires kernel mode");
                }
                pit_hw.counting = true;
                cout << "PIT started\n";
                continue;
            }
            
            // KBDPUSH - Push scancode to keyboard buffer (simulates keypress)
            // Syntax: KBDPUSH scancode
            if (op == "KBDPUSH") {
                if (current_privilege_level != 0) {
                    throw runtime_error("KBDPUSH: requires kernel mode");
    }
    if (toks.size() < 2) throw runtime_error("KBDPUSH needs 1 argument");
    
                u8 scancode = (u8)parse_int(toks[1]);
                keyboard_hw.scancode_queue.push(scancode);
                
                if (keyboard_hw.cycles_until_next_key == 0) {
                    keyboard_hw.cycles_until_next_key = 10;  // Start processing
                }
                
                cout << "Queued keyboard scancode 0x" << hex << (int)scancode << dec << "\n";
                continue;
            }
            
            // KBDCFG - Configure keyboard
            // Syntax: KBDCFG interrupt_num delay
            if (op == "KBDCFG") {
                if (current_privilege_level != 0) {
                    throw runtime_error("KBDCFG: requires kernel mode");
                }
                if (toks.size() < 3) throw runtime_error("KBDCFG needs 2 arguments");
                
                keyboard_hw.interrupt_number = (u8)parse_int(toks[1]);
                keyboard_hw.typematic_delay = parse_int(toks[2]);
                keyboard_hw.interrupt_enabled = true;
    
                cout << "Keyboard configured: IRQ=" << (int)keyboard_hw.interrupt_number 
                     << ", delay=" << keyboard_hw.typematic_delay << "\n";
                continue;
            }
            
            // SERIALCFG - Configure serial port
            // Syntax: SERIALCFG port_num interrupt_num baud_delay
            if (op == "SERIALCFG") {
                if (current_privilege_level != 0) {
                    throw runtime_error("SERIALCFG: requires kernel mode");
                }
                if (toks.size() < 4) throw runtime_error("SERIALCFG needs 3 arguments");
    
                u8 port = (u8)parse_int(toks[1]);
                if (port >= 4) throw runtime_error("SERIALCFG: port must be 0-3");
    
                serial_hw[port].interrupt_number = (u8)parse_int(toks[2]);
                serial_hw[port].baud_delay = parse_int(toks[3]);
                serial_hw[port].tx_interrupt_enabled = true;
                serial_hw[port].rx_interrupt_enabled = true;
                
                cout << "Serial port " << (int)port << " configured: IRQ=" 
                     << (int)serial_hw[port].interrupt_number << "\n";
                continue;
            }
            
            // SERIALTX - Transmit byte via serial (triggers interrupt when done)
            // Syntax: SERIALTX port_num byte
            if (op == "SERIALTX") {
                if (toks.size() < 3) throw runtime_error("SERIALTX needs 2 arguments");
                
                u8 port = (u8)parse_int(toks[1]);
                if (port >= 4) throw runtime_error("SERIALTX: port must be 0-3");
                
                u8 byte = 0;
                if (is_r8(toks[2])) byte = regs8[get_r8_index(toks[2])];
                else if (is_number(toks[2])) byte = (u8)parse_int(toks[2]);
                else throw runtime_error("SERIALTX: byte must be r8 or immediate");
                
                serial_hw[port].tx_buffer.push(byte);
                serial_hw[port].cycles_until_tx_ready = serial_hw[port].baud_delay;
                
                cout << "Queued serial TX on port " << (int)port << "\n";
                continue;
            }
            
            // SERIALRX - Simulate receiving byte via serial
            // Syntax: SERIALRX port_num byte
            if (op == "SERIALRX") {
                if (current_privilege_level != 0) {
                    throw runtime_error("SERIALRX: requires kernel mode");
                }
                if (toks.size() < 3) throw runtime_error("SERIALRX needs 2 arguments");
                
                u8 port = (u8)parse_int(toks[1]);
                if (port >= 4) throw runtime_error("SERIALRX: port must be 0-3");
                
                u8 byte = (u8)parse_int(toks[2]);
                
                serial_hw[port].pending_rx_byte = byte;
                serial_hw[port].has_pending_rx = true;
                serial_hw[port].cycles_until_rx_ready = serial_hw[port].baud_delay;
                
                cout << "Simulated serial RX on port " << (int)port << ": 0x" 
                     << hex << (int)byte << dec << "\n";
                continue;
            }
            
            // DISKCMD - Start disk operation (triggers interrupt when done)
            // Syntax: DISKCMD delay
            if (op == "DISKCMD") {
                if (toks.size() < 2) throw runtime_error("DISKCMD needs 1 argument");
                
                u32 delay = parse_int(toks[1]);
                
                disk_hw.operation_pending = true;
                disk_hw.cycles_until_complete = delay;
                disk_hw.last_status = 0x80;  // BSY (busy)
                
                cout << "Disk operation started (" << delay << " cycles)\n";
                continue;
            }
            
            // DISKCFG - Configure disk controller
            // Syntax: DISKCFG interrupt_num operation_delay
            if (op == "DISKCFG") {
                if (current_privilege_level != 0) {
                    throw runtime_error("DISKCFG: requires kernel mode");
                }
                if (toks.size() < 3) throw runtime_error("DISKCFG needs 2 arguments");
                
                disk_hw.interrupt_number = (u8)parse_int(toks[1]);
                disk_hw.operation_delay = parse_int(toks[2]);
                disk_hw.interrupt_enabled = true;
                
                cout << "Disk configured: IRQ=" << (int)disk_hw.interrupt_number << "\n";
                continue;
            }
            
            // RTCCFG - Configure RTC periodic interrupt
            // Syntax: RTCCFG interrupt_num interval
            if (op == "RTCCFG") {
                if (current_privilege_level != 0) {
                    throw runtime_error("RTCCFG: requires kernel mode");
                }
                if (toks.size() < 3) throw runtime_error("RTCCFG needs 2 arguments");
    
                rtc_hw.interrupt_number = (u8)parse_int(toks[1]);
                rtc_hw.periodic_interval = parse_int(toks[2]);
                rtc_hw.cycles_until_tick = rtc_hw.periodic_interval;
                rtc_hw.interrupt_enabled = true;
                
                cout << "RTC configured: IRQ=" << (int)rtc_hw.interrupt_number 
                     << ", interval=" << rtc_hw.periodic_interval << "\n";
                continue;
            }
            
            // RTCSTOP - Stop RTC interrupts
            if (op == "RTCSTOP") {
                if (current_privilege_level != 0) {
                    throw runtime_error("RTCSTOP: requires kernel mode");
                }
                rtc_hw.interrupt_enabled = false;
                            cout << "RTC stopped\n";
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

            
            // ==================== AES INSTRUCTIONS ====================
            
            // AESENC - AES Single Round Encryption
            // Syntax: AESENC key_reg state_reg
            // Performs one round of AES encryption on 128-bit state using round key
            // State is in r16_0-r16_7 (16 bytes), Key is in r16_8-r16_15
            if (op == "AESENC") {
                if (toks.size() < 3) throw runtime_error("AESENC needs 2 arguments: key_reg_base state_reg_base");
                string key_base = toks[1], state_base = toks[2];
                
                // Extract base register indices
                int key_idx = 0, state_idx = 0;
                if (is_r16(key_base)) key_idx = get_r16_index(key_base);
                else throw runtime_error("AESENC: key_base must be r16 register");
                
                if (is_r16(state_base)) state_idx = get_r16_index(state_base);
                else throw runtime_error("AESENC: state_base must be r16 register");
                
                // AES S-Box (simplified version for demonstration)
                static const u8 sbox[256] = {
                    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
                };
                
                // Load 128-bit state (16 bytes from 8 r16 registers)
                u8 state[16];
                for (int i = 0; i < 8; i++) {
                    state[i*2] = regs16[state_idx + i] & 0xFF;
                    state[i*2+1] = (regs16[state_idx + i] >> 8) & 0xFF;
                }
                
                // Load round key
                u8 key[16];
                for (int i = 0; i < 8; i++) {
                    key[i*2] = regs16[key_idx + i] & 0xFF;
                    key[i*2+1] = (regs16[key_idx + i] >> 8) & 0xFF;
                }
                
                // SubBytes
                for (int i = 0; i < 16; i++) {
                    state[i] = sbox[state[i]];
                }
                
                // ShiftRows (simplified for 128-bit)
                u8 temp;
                // Row 1: shift left by 1
                temp = state[1];
                state[1] = state[5];
                state[5] = state[9];
                state[9] = state[13];
                state[13] = temp;
                
                // Row 2: shift left by 2
                temp = state[2];
                state[2] = state[10];
                state[10] = temp;
                temp = state[6];
                state[6] = state[14];
                state[14] = temp;
                
                // Row 3: shift left by 3
                temp = state[15];
                state[15] = state[11];
                state[11] = state[7];
                state[7] = state[3];
                state[3] = temp;
                
                // MixColumns (simplified - just XOR for demonstration)
                for (int i = 0; i < 16; i += 4) {
                    u8 t = state[i] ^ state[i+1] ^ state[i+2] ^ state[i+3];
                    state[i] ^= t;
                    state[i+1] ^= t;
                    state[i+2] ^= t;
                    state[i+3] ^= t;
                }
                
                // AddRoundKey
                for (int i = 0; i < 16; i++) {
                    state[i] ^= key[i];
                }
                
                // Store result back
                for (int i = 0; i < 8; i++) {
                    regs16[state_idx + i] = state[i*2] | (state[i*2+1] << 8);
                }
                
                cout << "AESENC: Performed AES encryption round\n";
                continue;
            }
            
            // AESDEC - AES Single Round Decryption
            // Syntax: AESDEC key_reg state_reg
            if (op == "AESDEC") {
                if (toks.size() < 3) throw runtime_error("AESDEC needs 2 arguments: key_reg_base state_reg_base");
                string key_base = toks[1], state_base = toks[2];
                
                int key_idx = 0, state_idx = 0;
                if (is_r16(key_base)) key_idx = get_r16_index(key_base);
                else throw runtime_error("AESDEC: key_base must be r16 register");
                
                if (is_r16(state_base)) state_idx = get_r16_index(state_base);
                else throw runtime_error("AESDEC: state_base must be r16 register");
                
                // AES Inverse S-Box
                static const u8 inv_sbox[256] = {
                    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
                };
                
                // Load state and key
                u8 state[16], key[16];
                for (int i = 0; i < 8; i++) {
                    state[i*2] = regs16[state_idx + i] & 0xFF;
                    state[i*2+1] = (regs16[state_idx + i] >> 8) & 0xFF;
                    key[i*2] = regs16[key_idx + i] & 0xFF;
                    key[i*2+1] = (regs16[key_idx + i] >> 8) & 0xFF;
                }
                
                // Inverse operations (reverse order from AESENC)
                // AddRoundKey
                for (int i = 0; i < 16; i++) {
                    state[i] ^= key[i];
                }
                
                // InvMixColumns (simplified)
                for (int i = 0; i < 16; i += 4) {
                    u8 t = state[i] ^ state[i+1] ^ state[i+2] ^ state[i+3];
                    state[i] ^= t;
                    state[i+1] ^= t;
                    state[i+2] ^= t;
                    state[i+3] ^= t;
                }
                
                // InvShiftRows
                u8 temp;
                // Row 1: shift right by 1 (= shift left by 3)
                temp = state[13];
                state[13] = state[9];
                state[9] = state[5];
                state[5] = state[1];
                state[1] = temp;
                
                // Row 2: shift right by 2
                temp = state[2];
                state[2] = state[10];
                state[10] = temp;
                temp = state[6];
                state[6] = state[14];
                state[14] = temp;
                
                // Row 3: shift right by 3 (= shift left by 1)
                temp = state[3];
                state[3] = state[7];
                state[7] = state[11];
                state[11] = state[15];
                state[15] = temp;
                
                // InvSubBytes
                for (int i = 0; i < 16; i++) {
                    state[i] = inv_sbox[state[i]];
                }
                
                // Store result
                for (int i = 0; i < 8; i++) {
                    regs16[state_idx + i] = state[i*2] | (state[i*2+1] << 8);
                }
                
                cout << "AESDEC: Performed AES decryption round\n";
                continue;
            }
            
            // AESIMC - AES Inverse Mix Columns
            // Syntax: AESIMC state_reg
            // Performs inverse mix columns transformation on state
            if (op == "AESIMC") {
                if (toks.size() < 2) throw runtime_error("AESIMC needs 1 argument: state_reg_base");
                string state_base = toks[1];
                
                int state_idx = 0;
                if (is_r16(state_base)) state_idx = get_r16_index(state_base);
                else throw runtime_error("AESIMC: state_base must be r16 register");
                
                // Load state
                u8 state[16];
                for (int i = 0; i < 8; i++) {
                    state[i*2] = regs16[state_idx + i] & 0xFF;
                    state[i*2+1] = (regs16[state_idx + i] >> 8) & 0xFF;
                }
                
                // Perform inverse mix columns (simplified)
                for (int i = 0; i < 16; i += 4) {
                    u8 a = state[i];
                    u8 b = state[i+1];
                    u8 c = state[i+2];
                    u8 d = state[i+3];
                    
                    state[i]   = a ^ b ^ c;
                    state[i+1] = b ^ c ^ d;
                    state[i+2] = c ^ d ^ a;
                    state[i+3] = d ^ a ^ b;
                }
                
                // Store result
                for (int i = 0; i < 8; i++) {
                    regs16[state_idx + i] = state[i*2] | (state[i*2+1] << 8);
                }
                
                continue;
            }
            
            // AESKEYGENASSIST - AES Key Generation Assist
            // Syntax: AESKEYGENASSIST rcon source_key dest
            // Assists in AES key expansion using round constant
            if (op == "AESKEYGENASSIST") {
                if (toks.size() < 4) throw runtime_error("AESKEYGENASSIST needs 3 arguments");
                string rcon_str = toks[1], src_key = toks[2], dst = toks[3];
                
                u8 rcon = 0;
                if (is_r8(rcon_str)) rcon = regs8[get_r8_index(rcon_str)];
                else if (is_number(rcon_str)) rcon = (u8)parse_int(rcon_str);
                else throw runtime_error("AESKEYGENASSIST: rcon must be r8 or immediate");
                
                int src_idx = 0, dst_idx = 0;
                if (is_r16(src_key)) src_idx = get_r16_index(src_key);
                else throw runtime_error("AESKEYGENASSIST: source must be r16");
                
                if (is_r16(dst)) dst_idx = get_r16_index(dst);
                else throw runtime_error("AESKEYGENASSIST: dest must be r16");
                
                // AES S-Box for key schedule
                static const u8 sbox[256] = {
                    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
                };
                
                // Extract last 4 bytes of source key
                u8 temp[4];
                temp[0] = (regs16[src_idx + 6] >> 8) & 0xFF;
                temp[1] = regs16[src_idx + 7] & 0xFF;
                temp[2] = (regs16[src_idx + 7] >> 8) & 0xFF;
                temp[3] = regs16[src_idx + 6] & 0xFF;
                
                // RotWord
                u8 t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;
                
                // SubWord
                for (int i = 0; i < 4; i++) {
                    temp[i] = sbox[temp[i]];
                }
                
                // XOR with Rcon
                temp[0] ^= rcon;
                
                // Store result
                regs16[dst_idx] = temp[0] | (temp[1] << 8);
                regs16[dst_idx + 1] = temp[2] | (temp[3] << 8);
                
                continue;
            }

            if (op == "AESENCLAST") {
                if (toks.size() < 3) throw runtime_error("AESENCLAST needs 2 arguments: key_reg_base state_reg_base");
                string key_base = toks[1], state_base = toks[2];
    
                int key_idx = 0, state_idx = 0;
                if (is_r16(key_base)) key_idx = get_r16_index(key_base);
                else throw runtime_error("AESENCLAST: key_base must be r16 register");
    
                if (is_r16(state_base)) state_idx = get_r16_index(state_base);
                else throw runtime_error("AESENCLAST: state_base must be r16 register");
    
                // AES S-Box
                static const u8 sbox[256] = {
                    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
                };
                
                // Load state and key
                u8 state[16], key[16];
                for (int i = 0; i < 8; i++) {
                    state[i*2] = regs16[state_idx + i] & 0xFF;
                    state[i*2+1] = (regs16[state_idx + i] >> 8) & 0xFF;
                    key[i*2] = regs16[key_idx + i] & 0xFF;
                    key[i*2+1] = (regs16[key_idx + i] >> 8) & 0xFF;
                }
                
                // SubBytes
                for (int i = 0; i < 16; i++) {
                    state[i] = sbox[state[i]];
                }
                
                // ShiftRows
                u8 temp;
                temp = state[1];
                state[1] = state[5];
                state[5] = state[9];
                state[9] = state[13];
                state[13] = temp;
                
                temp = state[2];
                state[2] = state[10];
                state[10] = temp;
                temp = state[6];
                state[6] = state[14];
                state[14] = temp;
                
                temp = state[15];
                state[15] = state[11];
                state[11] = state[7];
                state[7] = state[3];
                state[3] = temp;
                
                // AddRoundKey (NO MixColumns in last round)
                for (int i = 0; i < 16; i++) {
                    state[i] ^= key[i];
                }
                
                // Store result
                for (int i = 0; i < 8; i++) {
                    regs16[state_idx + i] = state[i*2] | (state[i*2+1] << 8);
                }
                
                cout << "AESENCLAST: Performed AES final encryption round\n";
                continue;
            }

            // AESDECLAST - AES Last Round Decryption
            // Syntax: AESDECLAST key_reg state_reg
            // Performs the final AES decryption round (no InvMixColumns)
            if (op == "AESDECLAST") {
                if (toks.size() < 3) throw runtime_error("AESDECLAST needs 2 arguments: key_reg_base state_reg_base");
                string key_base = toks[1], state_base = toks[2];
    
                int key_idx = 0, state_idx = 0;
                if (is_r16(key_base)) key_idx = get_r16_index(key_base);
                else throw runtime_error("AESDECLAST: key_base must be r16 register");
    
                if (is_r16(state_base)) state_idx = get_r16_index(state_base);
                else throw runtime_error("AESDECLAST: state_base must be r16 register");
                
                // AES Inverse S-Box
                static const u8 inv_sbox[256] = {
                    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
                };
                
                // Load state and key
                u8 state[16], key[16];
                for (int i = 0; i < 8; i++) {
                    state[i*2] = regs16[state_idx + i] & 0xFF;
                    state[i*2+1] = (regs16[state_idx + i] >> 8) & 0xFF;
                    key[i*2] = regs16[key_idx + i] & 0xFF;
                    key[i*2+1] = (regs16[key_idx + i] >> 8) & 0xFF;
                }
                
                // AddRoundKey
                for (int i = 0; i < 16; i++) {
                    state[i] ^= key[i];
                }
                
                // InvShiftRows
                u8 temp;
                temp = state[13];
                state[13] = state[9];
                state[9] = state[5];
                state[5] = state[1];
                state[1] = temp;
                
                temp = state[2];
                state[2] = state[10];
                state[10] = temp;
                temp = state[6];
                state[6] = state[14];
                state[14] = temp;
                
                temp = state[3];
                state[3] = state[7];
                state[7] = state[11];
                state[11] = state[15];
                state[15] = temp;
                
                // InvSubBytes (NO InvMixColumns in last round)
                for (int i = 0; i < 16; i++) {
                    state[i] = inv_sbox[state[i]];
                }
                
                // Store result
                for (int i = 0; i < 8; i++) {
                    regs16[state_idx + i] = state[i*2] | (state[i*2+1] << 8);
                }
                
                cout << "AESDECLAST: Performed AES final decryption round\n";
                continue;
            }
            
            // SHA256RNDS2 - SHA-256 Rounds 2
            // Syntax: SHA256RNDS2 wk msg state
            // Performs 2 rounds of SHA-256 compression
            if (op == "SHA256RNDS2") {
                if (toks.size() < 4) throw runtime_error("SHA256RNDS2 needs 3 arguments: wk msg state");
                string wk_reg = toks[1], msg_reg = toks[2], state_reg = toks[3];
                
                int wk_idx = 0, msg_idx = 0, state_idx = 0;
                if (is_r16(wk_reg)) wk_idx = get_r16_index(wk_reg);
                else throw runtime_error("SHA256RNDS2: wk must be r16");
                if (is_r16(msg_reg)) msg_idx = get_r16_index(msg_reg);
                else throw runtime_error("SHA256RNDS2: msg must be r16");
                if (is_r16(state_reg)) state_idx = get_r16_index(state_reg);
                else throw runtime_error("SHA256RNDS2: state must be r16");
                
                // Load state (8 x 32-bit = 16 bytes, using 8 r16 registers)
                u32 state[8];
                for (int i = 0; i < 8; i++) {
                    u32 low = regs16[state_idx + i];
                    u32 high = regs16[state_idx + i + 1];
                    state[i] = low | (high << 16);
                }
                
                // Load message schedule words
                u32 w0 = regs16[msg_idx] | ((u32)regs16[msg_idx + 1] << 16);
                u32 w1 = regs16[msg_idx + 2] | ((u32)regs16[msg_idx + 3] << 16);
                
            // Load K constants
            u32 k0 = regs16[wk_idx] | ((u32)regs16[wk_idx + 1] << 16);
            u32 k1 = regs16[wk_idx + 2] | ((u32)regs16[wk_idx + 3] << 16);
                
                // SHA-256 functions
                auto ROTR = [](u32 x, int n) -> u32 { return (x >> n) | (x << (32 - n)); };
                auto CH = [](u32 x, u32 y, u32 z) -> u32 { return (x & y) ^ (~x & z); };
                auto MAJ = [](u32 x, u32 y, u32 z) -> u32 { return (x & y) ^ (x & z) ^ (y & z); };
                auto SIGMA0 = [&](u32 x) -> u32 { return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22); };
                auto SIGMA1 = [&](u32 x) -> u32 { return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25); };
                
                // Perform 2 rounds
                for (int round = 0; round < 2; round++) {
                    u32 w = (round == 0) ? w0 : w1;
                    u32 k = (round == 0) ? k0 : k1;
                    
                    u32 a = state[0], b = state[1], c = state[2], d = state[3];
                    u32 e = state[4], f = state[5], g = state[6], h = state[7];
                    
                    u32 t1 = h + SIGMA1(e) + CH(e, f, g) + k + w;
                    u32 t2 = SIGMA0(a) + MAJ(a, b, c);
                    
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                    
                    state[0] = a; state[1] = b; state[2] = c; state[3] = d;
                    state[4] = e; state[5] = f; state[6] = g; state[7] = h;
                }
                
                // Store result
                for (int i = 0; i < 4; i++) {
                    regs16[state_idx + i*2] = state[i*2] & 0xFFFF;
                    regs16[state_idx + i*2 + 1] = (state[i*2] >> 16) & 0xFFFF;
                }
                
                continue;
            }
            
            // SHA256MSG2 - SHA-256 Message Schedule 4-7
            // Syntax: SHA256MSG2 src dest
            // Completes SHA-256 message schedule expansion
            if (op == "SHA256MSG2") {
                if (toks.size() < 3) throw runtime_error("SHA256MSG2 needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                int src_idx = 0, dst_idx = 0;
                if (is_r16(src)) src_idx = get_r16_index(src);
                else throw runtime_error("SHA256MSG2: src must be r16");
                if (is_r16(dst)) dst_idx = get_r16_index(dst);
                else throw runtime_error("SHA256MSG2: dest must be r16");
                
                // Load values
                u32 W[4], M[4];
                for (int i = 0; i < 2; i++) {
                    W[i*2] = regs16[dst_idx + i*2] | ((u32)regs16[dst_idx + i*2 + 1] << 16);
                    W[i*2+1] = W[i*2];  // Duplicate for simplicity
                    M[i*2] = regs16[src_idx + i*2] | ((u32)regs16[src_idx + i*2 + 1] << 16);
                    M[i*2+1] = M[i*2];
                }
                
                // SHA-256 sigma1 function
                auto ROTR = [](u32 x, int n) -> u32 { return (x >> n) | (x << (32 - n)); };
                auto sigma1 = [&](u32 x) -> u32 {
                    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
                };
                
                // Complete message schedule: W[i] = W[i] + sigma1(M[i+14])
                for (int i = 0; i < 4; i++) {
                    W[i] += sigma1(M[i]);
                }
                
                // Store result
                for (int i = 0; i < 2; i++) {
                    regs16[dst_idx + i*2] = W[i*2] & 0xFFFF;
                    regs16[dst_idx + i*2 + 1] = (W[i*2] >> 16) & 0xFFFF;
                }
                
                continue;
            }
            
            // SHA1RNDS4 - SHA-1 Rounds 4
            // Syntax: SHA1RNDS4 func wk state
            // Performs 4 rounds of SHA-1 compression
            if (op == "SHA1RNDS4") {
                if (toks.size() < 4) throw runtime_error("SHA1RNDS4 needs 3 arguments: func wk state");
                string func_str = toks[1], wk_reg = toks[2], state_reg = toks[3];
                
                u8 func = 0;
                if (is_r8(func_str)) func = regs8[get_r8_index(func_str)];
                else if (is_number(func_str)) func = (u8)parse_int(func_str);
                else throw runtime_error("SHA1RNDS4: func must be r8 or immediate (0-3)");
                
                int wk_idx = 0, state_idx = 0;
                if (is_r16(wk_reg)) wk_idx = get_r16_index(wk_reg);
                else throw runtime_error("SHA1RNDS4: wk must be r16");
                if (is_r16(state_reg)) state_idx = get_r16_index(state_reg);
                else throw runtime_error("SHA1RNDS4: state must be r16");
                
                // Load state (5 x 32-bit values)
                u32 a = regs16[state_idx] | ((u32)regs16[state_idx + 1] << 16);
                u32 b = regs16[state_idx + 2] | ((u32)regs16[state_idx + 3] << 16);
                u32 c = regs16[state_idx + 4] | ((u32)regs16[state_idx + 5] << 16);
                u32 d = regs16[state_idx + 6] | ((u32)regs16[state_idx + 7] << 16);
                u32 e = regs16[wk_idx + 6] | ((u32)regs16[wk_idx + 7] << 16);  // E from WK
                
                // Load message words
                u32 w[4];
                for (int i = 0; i < 4; i++) {
                    w[i] = regs16[wk_idx + i*2] | ((u32)regs16[wk_idx + i*2 + 1] << 16);
                }
                
                auto ROTL = [](u32 x, int n) -> u32 { return (x << n) | (x >> (32 - n)); };
                
                // SHA-1 functions based on round
                auto F = [func](u32 b, u32 c, u32 d) -> u32 {
                    switch (func & 3) {
                        case 0: return (b & c) | (~b & d);  // CH
                        case 1: return b ^ c ^ d;            // PARITY
                        case 2: return (b & c) | (b & d) | (c & d);  // MAJ
                        case 3: return b ^ c ^ d;            // PARITY
                    }
                    return 0;
                };
                
                // K constants
                static const u32 K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
                
                // Perform 4 rounds
                for (int round = 0; round < 4; round++) {
                    u32 temp = ROTL(a, 5) + F(b, c, d) + e + K[func & 3] + w[round];
                    e = d;
                    d = c;
                    c = ROTL(b, 30);
                    b = a;
                    a = temp;
                }
                
                // Store result
                regs16[state_idx] = a & 0xFFFF;
                regs16[state_idx + 1] = (a >> 16) & 0xFFFF;
                regs16[state_idx + 2] = b & 0xFFFF;
                regs16[state_idx + 3] = (b >> 16) & 0xFFFF;
                regs16[state_idx + 4] = c & 0xFFFF;
                regs16[state_idx + 5] = (c >> 16) & 0xFFFF;
                regs16[state_idx + 6] = d & 0xFFFF;
                regs16[state_idx + 7] = (d >> 16) & 0xFFFF;
                
                continue;
            }

            // SHA1NEXTE - SHA-1 Next E
            // Syntax: SHA1NEXTE src dest
            // Calculates next E value for SHA-1
            if (op == "SHA1NEXTE") {
                if (toks.size() < 3) throw runtime_error("SHA1NEXTE needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                int src_idx = 0, dst_idx = 0;
                if (is_r16(src)) src_idx = get_r16_index(src);
                else throw runtime_error("SHA1NEXTE: src must be r16");
                if (is_r16(dst)) dst_idx = get_r16_index(dst);
                else throw runtime_error("SHA1NEXTE: dest must be r16");
                
                // Load E value from source (first 32 bits)
                u32 e = regs16[src_idx] | ((u32)regs16[src_idx + 1] << 16);
                
                // Load current state from dest
                u32 state0 = regs16[dst_idx] | ((u32)regs16[dst_idx + 1] << 16);
                
                // Calculate next E: E0 + state0
                u32 next_e = e + state0;
                
                // Store in first position of dest
                regs16[dst_idx] = next_e & 0xFFFF;
                regs16[dst_idx + 1] = (next_e >> 16) & 0xFFFF;
                
                continue;
            }
            
            // SHA1MSG1 - SHA-1 Message Schedule 1
            // Syntax: SHA1MSG1 src dest
            // First step of SHA-1 message schedule
            if (op == "SHA1MSG1") {
                if (toks.size() < 3) throw runtime_error("SHA1MSG1 needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                int src_idx = 0, dst_idx = 0;
                if (is_r16(src)) src_idx = get_r16_index(src);
                else throw runtime_error("SHA1MSG1: src must be r16");
                if (is_r16(dst)) dst_idx = get_r16_index(dst);
                else throw runtime_error("SHA1MSG1: dest must be r16");
                
                // Load values (4 x 32-bit words)
                u32 W[4], M[4];
                for (int i = 0; i < 2; i++) {
                    W[i*2] = regs16[dst_idx + i*2] | ((u32)regs16[dst_idx + i*2 + 1] << 16);
                    W[i*2+1] = W[i*2];
                    M[i*2] = regs16[src_idx + i*2] | ((u32)regs16[src_idx + i*2 + 1] << 16);
                    M[i*2+1] = M[i*2];
                }
                
                // XOR operation for message schedule
                for (int i = 0; i < 4; i++) {
                    W[i] ^= M[i];
                }
                
                // Store result
                for (int i = 0; i < 2; i++) {
                    regs16[dst_idx + i*2] = W[i*2] & 0xFFFF;
                    regs16[dst_idx + i*2 + 1] = (W[i*2] >> 16) & 0xFFFF;
                }
                
                continue;
            }
            
            // SHA1MSG2 - SHA-1 Message Schedule 2
            // Syntax: SHA1MSG2 src dest
            // Final step of SHA-1 message schedule
            if (op == "SHA1MSG2") {
                if (toks.size() < 3) throw runtime_error("SHA1MSG2 needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                int src_idx = 0, dst_idx = 0;
                if (is_r16(src)) src_idx = get_r16_index(src);
                else throw runtime_error("SHA1MSG2: src must be r16");
                if (is_r16(dst)) dst_idx = get_r16_index(dst);
                else throw runtime_error("SHA1MSG2: dest must be r16");
                
                // Load destination values (4 x 32-bit words from 8 x 16-bit registers)
                u32 W[4];
                for (int i = 0; i < 4; i++) {
                    W[i] = regs16[dst_idx + i*2] | ((u32)regs16[dst_idx + i*2 + 1] << 16);
                }
                
                // Load source values (4 x 32-bit words from 8 x 16-bit registers)
                u32 M[4];
                for (int i = 0; i < 4; i++) {
                    M[i] = regs16[src_idx + i*2] | ((u32)regs16[src_idx + i*2 + 1] << 16);
                }
                
                auto ROTL = [](u32 x, int n) -> u32 { return (x << n) | (x >> (32 - n)); };
                
                // XOR each W with corresponding M, then rotate all
                for (int i = 0; i < 4; i++) {
                    W[i] = ROTL(W[i] ^ M[i], 1);
                }
                
                // Store all 4 results back
                for (int i = 0; i < 4; i++) {
                    regs16[dst_idx + i*2] = W[i] & 0xFFFF;
                    regs16[dst_idx + i*2 + 1] = (W[i] >> 16) & 0xFFFF;
                }
                
                continue;
            }
            
            // ADCX - Add with Carry (uses CF, doesn't modify other flags)
            // Syntax: ADCX source destination
            // dest = dest + source + CF, updates only CF
            if (op == "ADCX") {
                if (toks.size() < 3) throw runtime_error("ADCX needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                bool is_16bit = false;
                u32 src_val = 0, dst_val = 0;
                
                // Get source value
                if (is_r8(src)) {
                    src_val = regs8[get_r8_index(src)];
                } else if (is_r16(src)) {
                    src_val = regs16[get_r16_index(src)];
                    is_16bit = true;
                } else if (is_number(src)) {
                    src_val = parse_int(src);
                } else {
                    throw runtime_error("ADCX: source must be register or immediate");
                }
                
                // Get destination value
                int dst_idx = -1;
                if (is_r8(dst)) {
                    dst_idx = get_r8_index(dst);
                    dst_val = regs8[dst_idx];
                } else if (is_r16(dst)) {
                    dst_idx = get_r16_index(dst);
                    dst_val = regs16[dst_idx];
                    is_16bit = true;
                } else {
                    throw runtime_error("ADCX: destination must be register");
                }
                
                // Perform addition with carry
                u32 result = dst_val + src_val + (CF ? 1 : 0);
                
                // Update only CF (carry flag)
                if (is_16bit) {
                    CF = (result > 0xFFFF);
                    regs16[dst_idx] = (u16)result;
                } else {
                    CF = (result > 0xFF);
                    regs8[dst_idx] = (u8)result;
                }
                
                // ADCX does NOT modify OF, SF, ZF, AF, PF
                continue;
            }
            
            // ADOX - Add with Overflow (uses OF, doesn't modify other flags)
            // Syntax: ADOX source destination
            // dest = dest + source + OF, updates only OF
            if (op == "ADOX") {
                if (toks.size() < 3) throw runtime_error("ADOX needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                bool is_16bit = false;
                u32 src_val = 0, dst_val = 0;
                
                // Get source value
                if (is_r8(src)) {
                    src_val = regs8[get_r8_index(src)];
                } else if (is_r16(src)) {
                    src_val = regs16[get_r16_index(src)];
                    is_16bit = true;
                } else if (is_number(src)) {
                    src_val = parse_int(src);
                } else {
                    throw runtime_error("ADOX: source must be register or immediate");
                }
                
                // Get destination value
                int dst_idx = -1;
                if (is_r8(dst)) {
                    dst_idx = get_r8_index(dst);
                    dst_val = regs8[dst_idx];
                } else if (is_r16(dst)) {
                    dst_idx = get_r16_index(dst);
                    dst_val = regs16[dst_idx];
                    is_16bit = true;
                } else {
                    throw runtime_error("ADOX: destination must be register");
                }
                
                // Perform addition with overflow flag
                u32 result = dst_val + src_val + (OF ? 1 : 0);
                
                // Update only OF (overflow flag)
                if (is_16bit) {
                    OF = (result > 0xFFFF);
                    regs16[dst_idx] = (u16)result;
                } else {
                    OF = (result > 0xFF);
                    regs8[dst_idx] = (u8)result;
                }
                
                // ADOX does NOT modify CF, SF, ZF, AF, PF
                continue;
            }
            
            // ==================== ADDITIONAL CRYPTO OPERATIONS ====================
            
            // CRC32 - Calculate CRC32 checksum
            // Syntax: CRC32 data_reg length_reg result_reg
            if (op == "CRC32") {
                if (toks.size() < 4) throw runtime_error("CRC32 needs 3 arguments");
                string data_reg = toks[1], len_reg = toks[2], result_reg = toks[3];
                
                u32 addr = 0;
                if (is_r16(data_reg)) addr = regs16[get_r16_index(data_reg)];
                else if (is_r8(data_reg)) addr = regs8[get_r8_index(data_reg)];
                else throw runtime_error("CRC32: data_reg must be register");
                
                u32 length = 0;
                if (is_r16(len_reg)) length = regs16[get_r16_index(len_reg)];
                else if (is_r8(len_reg)) length = regs8[get_r8_index(len_reg)];
                else if (is_number(len_reg)) length = parse_int(len_reg);
                else throw runtime_error("CRC32: length must be register or immediate");
                
                // CRC32 polynomial (IEEE 802.3)
                u32 crc = 0xFFFFFFFF;
                for (u32 i = 0; i < length; i++) {
                    u8 byte = mem_read8_at(addr + i);
                    crc ^= byte;
                    for (int j = 0; j < 8; j++) {
                        if (crc & 1) {
                            crc = (crc >> 1) ^ 0xEDB88320;
                        } else {
                            crc >>= 1;
                        }
                    }
                }
                crc ^= 0xFFFFFFFF;
                
                // Store result (lower 16 bits)
                if (is_r16(result_reg)) {
                    regs16[get_r16_index(result_reg)] = crc & 0xFFFF;
                    if (get_r16_index(result_reg) + 1 < 32) {
                        regs16[get_r16_index(result_reg) + 1] = (crc >> 16) & 0xFFFF;
                    }
                } else if (is_r8(result_reg)) {
                    regs8[get_r8_index(result_reg)] = crc & 0xFF;
                } else {
                    throw runtime_error("CRC32: result must be register");
                }
                
                continue;
            }
            
            // PCLMULQDQ - Carry-less Multiplication (used in AES-GCM)
            // Syntax: PCLMULQDQ src1 src2 dest
            // Performs carry-less multiplication of two 64-bit values
            if (op == "PCLMULQDQ") {
                if (toks.size() < 4) throw runtime_error("PCLMULQDQ needs 3 arguments");
                string src1 = toks[1], src2 = toks[2], dst = toks[3];
                
                // Get source values (as pairs of r16 registers)
                u32 a = 0, b = 0;
                if (is_r16(src1)) {
                    int idx = get_r16_index(src1);
                    a = regs16[idx] | ((u32)regs16[idx+1] << 16);
                } else throw runtime_error("PCLMULQDQ: src1 must be r16");
                
                if (is_r16(src2)) {
                    int idx = get_r16_index(src2);
                    b = regs16[idx] | ((u32)regs16[idx+1] << 16);
                } else throw runtime_error("PCLMULQDQ: src2 must be r16");
                
                // Carry-less multiplication (GF(2) polynomial multiplication)
                u32 result_low = 0, result_high = 0;
                for (int i = 0; i < 32; i++) {
                    if (b & 1) {
                        result_low ^= (a << i);
                        if (i > 0) result_high ^= (a >> (32 - i));
                    }
                    b >>= 1;
                }
                
                // Store result in destination (4 r16 registers for 64-bit result)
                if (is_r16(dst)) {
                    int idx = get_r16_index(dst);
                    regs16[idx] = result_low & 0xFFFF;
                    regs16[idx+1] = (result_low >> 16) & 0xFFFF;
                    if (idx + 2 < 32) regs16[idx+2] = result_high & 0xFFFF;
                    if (idx + 3 < 32) regs16[idx+3] = (result_high >> 16) & 0xFFFF;
                } else throw runtime_error("PCLMULQDQ: dest must be r16");
                
                continue;
            }
            
            // SHA256MSG1 - SHA-256 Message Schedule 0-3
            // Syntax: SHA256MSG1 src dest
            // Performs first part of SHA-256 message schedule expansion
            if (op == "SHA256MSG1") {
                if (toks.size() < 3) throw runtime_error("SHA256MSG1 needs 2 arguments");
                string src = toks[1], dst = toks[2];
                
                int src_idx = 0, dst_idx = 0;
                if (is_r16(src)) src_idx = get_r16_index(src);
                else throw runtime_error("SHA256MSG1: src must be r16");
                
                if (is_r16(dst)) dst_idx = get_r16_index(dst);
                else throw runtime_error("SHA256MSG1: dest must be r16");
                
                // Load 128-bit values (4 x 32-bit words)
                u32 W[4], M[4];
                for (int i = 0; i < 2; i++) {
                    W[i*2] = regs16[dst_idx + i*2] | ((u32)regs16[dst_idx + i*2 + 1] << 16);
                    W[i*2+1] = regs16[dst_idx + i*2 + 2] | ((u32)regs16[dst_idx + i*2 + 3] << 16);
                    M[i*2] = regs16[src_idx + i*2] | ((u32)regs16[src_idx + i*2 + 1] << 16);
                    M[i*2+1] = regs16[src_idx + i*2] | ((u32)regs16[src_idx + i*2 + 1] << 16);
                }
                
                // SHA-256 sigma0 function
                auto sigma0 = [](u32 x) -> u32 {
                    return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
                };
                
                // Compute W[i] = W[i] + sigma0(W[i+1])
                for (int i = 0; i < 4; i++) {
                    W[i] += sigma0(M[(i+1) % 4]);
                }
                
                // Store result
                for (int i = 0; i < 2; i++) {
                    regs16[dst_idx + i*2] = W[i*2] & 0xFFFF;
                    regs16[dst_idx + i*2 + 1] = (W[i*2] >> 16) & 0xFFFF;
                }
                
                continue;
            }
            
            // RDRAND - Read Random Number (hardware RNG)
            // Syntax: RDRAND dest
            // Fills destination register with random data
            if (op == "RDRAND") {
                if (toks.size() < 2) throw runtime_error("RDRAND needs 1 argument");
                string dst = toks[1];
                
                // Generate random number using hardware cycle counter + simple PRNG
                u32 rand_val = (hardware_cycle_counter * 1103515245 + 12345) & 0x7FFFFFFF;
                
                if (is_r8(dst)) {
                    regs8[get_r8_index(dst)] = rand_val & 0xFF;
                    CF = true;  // Success
                } else if (is_r16(dst)) {
                    regs16[get_r16_index(dst)] = rand_val & 0xFFFF;
                    CF = true;
                } else {
                    throw runtime_error("RDRAND: dest must be register");
                }
                
                continue;
            }
            
            // RDSEED - Read Random Seed (entropy source)
            // Syntax: RDSEED dest
            // Similar to RDRAND but intended for seeding PRNGs
            if (op == "RDSEED") {
                if (toks.size() < 2) throw runtime_error("RDSEED needs 1 argument");
                string dst = toks[1];
                
                // Use different mixing for seed vs random
                u32 seed_val = ((hardware_cycle_counter ^ 0xDEADBEEF) * 2654435761) & 0xFFFFFFFF;
                
                if (is_r8(dst)) {
                    regs8[get_r8_index(dst)] = seed_val & 0xFF;
                    CF = true;
                } else if (is_r16(dst)) {
                    regs16[get_r16_index(dst)] = seed_val & 0xFFFF;
                    CF = true;
                } else {
                    throw runtime_error("RDSEED: dest must be register");
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