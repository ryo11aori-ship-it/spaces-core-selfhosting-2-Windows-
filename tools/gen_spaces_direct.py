#!/usr/bin/env python3
# tools/gen_spaces_direct.py
# Spaces Compiler Generator (Unrolled Mode)
# Fix: Dynamic calculation of offsets and sizes to prevent "off-by-N" errors.
#      No loops in Spaces code -> Guaranteed termination.

import sys
import struct

def p64(val):
    return list(val.to_bytes(8, 'little'))

def p32(val):
    return list(val.to_bytes(4, 'little'))

def main():
    # --- 1. Prepare Content ---
    
    # Message
    msg = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a] # "Hello, world!\n"
    
    # Header size is fixed (64-bit ELF header + 1 Program Header)
    # ELF Header (64) + Program Header (56) = 120 bytes
    header_len = 120
    
    # --- 2. Construct Code with Placeholder Address ---
    # We don't know msg_addr yet, but we can determine code length.
    
    # Machine Code Template
    # mov eax, 1; mov edi, 1; mov rsi, 0x????????????????; mov edx, 14; syscall; mov eax, 60; xor edi, edi; syscall
    # We use a placeholder for RSI
    code_part1 = [
        0xb8, 0x01, 0x00, 0x00, 0x00,       # mov eax, 1
        0xbf, 0x01, 0x00, 0x00, 0x00,       # mov edi, 1
        0x48, 0xbe                          # mov rsi, ...
    ]
    # Placeholder for 64-bit address (8 bytes)
    code_placeholder = [0x00] * 8
    
    code_part2 = [
        0xba, 0x0e, 0x00, 0x00, 0x00,       # mov edx, 14
        0x0f, 0x05,                         # syscall
        0xb8, 0x3c, 0x00, 0x00, 0x00,       # mov eax, 60
        0x31, 0xff,                         # xor edi, edi
        0x0f, 0x05                          # syscall
    ]
    
    # Temporary code just to get length
    temp_code = code_part1 + code_placeholder + code_part2
    code_len = len(temp_code)
    
    # --- 3. Calculate Addresses ---
    load_addr = 0x400000
    msg_offset = header_len + code_len
    msg_addr = load_addr + msg_offset
    
    # --- 4. Finalize Code ---
    # Put the correct address
    final_code = code_part1 + p64(msg_addr) + code_part2
    
    # --- 5. Construct Header ---
    total_size = header_len + code_len + len(msg)
    
    elf_header = [
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0,0,0,0,0,0,0,0,
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
        # Entry point: Start of code (after header)
        *p64(load_addr + header_len),
        *p64(64), # Phoff
        *p64(0),  # Shoff
        *p32(0),  # Flags
        0x40, 0x00, # Ehsize (64)
        0x38, 0x00, # Phentsize (56)
        0x01, 0x00, # Phnum
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00 # Shentsize, Shnum, Shstrndx
    ]
    
    prog_header = [
        0x01, 0x00, 0x00, 0x00, # Type LOAD
        0x07, 0x00, 0x00, 0x00, # Flags RWE
        *p64(0), # Offset
        *p64(load_addr), # Vaddr
        *p64(load_addr), # Paddr
        *p64(total_size), # Filesz (Exact size)
        *p64(total_size), # Memsz  (Exact size)
        *p64(0x1000)      # Align
    ]
    
    # --- 6. Assemble Binary ---
    binary = elf_header + prog_header + final_code + msg
    
    # Check size match
    if len(binary) != total_size:
        # Should not happen with dynamic calc, but good safety
        raise ValueError(f"Size mismatch: Calc {total_size} vs Actual {len(binary)}")

    # --- 7. Generate Spaces Code ---
    # Unrolled: Output bytes one by one using minimal Spaces ops
    S = " "      # Space
    F = "\u3000" # Fullwidth Space
    cmds = []
    
    current_val = 0
    for byte in binary:
        diff = byte - current_val
        if diff > 0:
            cmds.append((S+F+S) * diff) # +
        elif diff < 0:
            cmds.append((S+F+F) * (-diff)) # -
        cmds.append(F+S+S) # .
        current_val = byte
        
    # Output to stdout
    sys.stdout.buffer.write("".join(cmds).encode('utf-8'))
    
    # Log
    with open("bf_debug.log", "w") as f:
        f.write(f"Generated Unrolled. Size: {total_size}. MsgAddr: {hex(msg_addr)}\n")

if __name__ == '__main__':
    main()
