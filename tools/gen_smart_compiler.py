#!/usr/bin/env python3
# tools/gen_smart_compiler.py
# Spaces Compiler Generator (Smart Mode)
# Fix: Corrected exit_code_index from 34 to 33.
#      Previous off-by-one error caused exit code to be 8192 (0x2000) instead of 32 (0x20).

import sys

def p64(val): return list(val.to_bytes(8, 'little'))
def p32(val): return list(val.to_bytes(4, 'little'))

def main():
    # --- 1. Target ELF Structure ---
    load_addr = 0x400000
    header_len = 120
    
    # Message: "Hello!\n" (7 bytes)
    msg = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x0a]
    
    # Machine Code Template
    code_template = [
        # write(1, msg, len)
        0xb8, 0x01, 0x00, 0x00, 0x00,       # 0-4: mov eax, 1
        0xbf, 0x01, 0x00, 0x00, 0x00,       # 5-9: mov edi, 1
        0x48, 0xbe,                         # 10-11: mov rsi, ...
        # (Address placeholder 8 bytes: 12-19)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0xba, len(msg), 0x00, 0x00, 0x00,   # 20-24: mov edx, 7
        0x0f, 0x05,                         # 25-26: syscall
        
        # exit(count)
        0xb8, 0x3c, 0x00, 0x00, 0x00,       # 27-31: mov eax, 60
        0xbf,                               # 32: mov edi (opcode)
        0x00, 0x00, 0x00, 0x00,             # 33-36: imm32 (The Exit Code)
        0x0f, 0x05                          # 37-38: syscall
    ]
    
    # Offsets
    code_len = len(code_template)
    msg_addr = load_addr + header_len + code_len
    
    # Inject Msg Address
    addr_bytes = p64(msg_addr)
    for i in range(8):
        code_template[12 + i] = addr_bytes[i]
        
    # Full Binary Size
    total_size = header_len + code_len + len(msg)
    
    # --- 2. Generate Spaces Code ---
    S = " "      # Space
    F = "\u3000" # Fullwidth Space
    cmds = []
    
    def emit_ops(s): cmds.append(s)
    
    # State tracking
    current_val = 0
    
    def emit_bytes(byte_list):
        nonlocal current_val
        for b in byte_list:
            diff = b - current_val
            if diff > 0: emit_ops((S+F+S) * diff)
            elif diff < 0: emit_ops((S+F+F) * (-diff))
            emit_ops(F+S+S) # Output
            current_val = b

    # A. Emit ELF Header
    elf_header = [
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0,0,0,0,0,0,0,0,
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
        *p64(load_addr + header_len), *p64(64), *p64(0), *p32(0),
        0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]
    prog_header = [
        0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        *p64(0), *p64(load_addr), *p64(load_addr),
        *p64(total_size), *p64(total_size), *p64(0x1000)
    ]
    
    emit_bytes(elf_header + prog_header)
    
    # B. Emit Machine Code Part 1 (Before Exit Code)
    # The LSB of the exit code is at index 33.
    exit_code_index = 33
    emit_bytes(code_template[:exit_code_index])
    
    # C. THE LOGIC (Dynamic Input Injection)
    # Move to C1, Read Input, Output C1 (as exit code byte), Reset C1
    
    # Reset C0 accumulator before switch
    if current_val > 0: emit_ops((S+F+F) * current_val)
    
    emit_ops(S+S+S) # > Move to C1
    emit_ops(F+S+F) # , Read Input (ASCII 32 ' ' expected)
    emit_ops(F+S+S) # . Output Input Byte (Injection!)
    
    # Reset C1 to 0 (Safe small loop)
    emit_ops(F+F+S + S+F+F + F+F+F) # [-]
    current_val = 0
    
    # D. Emit Machine Code Part 2 (After Exit Code)
    # Skip index 33 because we just output it dynamically
    emit_bytes(code_template[exit_code_index+1:])
    
    # E. Emit Message
    emit_bytes(msg)

    # Output
    sys.stdout.buffer.write("".join(cmds).encode('utf-8'))
    with open("bf_debug.log", "w") as f: f.write("Generated Smart Compiler (Index 33 Fixed).\n")

if __name__ == '__main__':
    main()
