#!/usr/bin/env python3
# tools/gen_compiler_bf_basic.py
# Level 1.5: Brainfuck Compiler (Basic 6 Commands)
# Fixed: Increased p_memsz in ELF header to avoid Segmentation Fault.
#        Now allocates 64KB memory so data pointer (0x402000) is valid.

import sys

# --- Spaces Ops ---
S = " "
F = "\u3000"

def emit(s): sys.stdout.write(s + "\n")
def right(n=1): emit((S+S+S)*n)
def left(n=1): emit((S+S+F)*n)
def inc(n=1): emit((S+F+S)*n)
def dec(n=1): emit((S+F+F)*n)
def out(): emit(F+S+S)
def inp(): emit(F+S+F)
def loop_open(): emit(F+F+S)
def loop_close(): emit(F+F+F)
def clear(): loop_open(); dec(); loop_close()

# --- Memory Layout ---
# C0: Input Char
# C1: Comparison Scratch
# C2: Main Loop Flag
# C3: Match Flag / Copy Backup
# C4: Padding Counter
# C7: Output Byte Counter
# C8: Output Buffer

def emit_byte_tracked(val):
    right(8); clear()
    if val > 0: inc(val)
    out(); clear(); left(8)
    right(7); inc(); left(7)

def emit_bytes(vals):
    for v in vals: emit_byte_tracked(v)

def copy_c0_to_c1():
    # Non-destructive copy C0 -> C1 (using C3 as backup)
    right(1); clear(); right(2); clear(); left(3)
    loop_open()
    dec(); right(1); inc(); right(2); inc(); left(3)
    loop_close()
    right(3)
    loop_open()
    dec(); left(3); inc(); right(3)
    loop_close()
    left(3)

def check_and_emit(char_code, bytes_to_emit):
    # Check if C0 == char_code. If so, emit bytes.
    copy_c0_to_c1()
    right(1); dec(char_code)
    # Check zero
    right(2); clear(); inc(); left(2) # C3=1
    loop_open(); right(2); clear(); left(2); clear(); loop_close()
    
    # If Match (C3==1)
    right(2)
    loop_open()
    left(3) # C0
    emit_bytes(bytes_to_emit)
    right(3); clear(); loop_close()
    left(3) # C0

def main():
    total_size = 500
    load_addr = 0x400000
    header_len = 120
    
    def p64(v): return list(v.to_bytes(8, "little"))
    def p32(v): return list(v.to_bytes(4, "little"))

    header = [
        0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0,0,0,0,0,0,0,0,
        0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,
        *p64(load_addr + header_len), *p64(64), *p64(0), *p32(0),
        0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    ]
    prog_header = [
        0x01,0x00,0x00,0x00,0x07,0x00,0x00,0x00,
        *p64(0), *p64(load_addr), *p64(load_addr),
        *p64(total_size),       # File Size (500 bytes)
        *p64(0x10000),          # Memory Size (64KB) <-- FIXED: Allocates plenty of RAM
        *p64(0x1000)
    ]
    
    # 1. ELF Header
    emit_bytes(header + prog_header)
    
    # 2. Init Code
    # mov rbx, 0x402000 (Data Pointer)
    emit_bytes([0x48, 0xc7, 0xc3, 0x00, 0x20, 0x40, 0x00])

    # 3. Main Loop
    right(2); clear(); inc(); left(2) # C2=1
    right(2); loop_open(); left(2) # Enter Loop
    
    clear(); inp()
    
    # EOF Check
    copy_c0_to_c1()
    right(3); clear(); inc(); left(2)
    loop_open(); right(2); clear(); left(2); clear(); loop_close()
    right(2); loop_open(); left(1); clear(); right(1); clear(); loop_close(); left(3)
    
    # --- Command Checks ---
    
    # > (62): inc rbx (48 FF C3)
    check_and_emit(62, [0x48, 0xff, 0xc3])
    
    # < (60): dec rbx (48 FF CB)
    check_and_emit(60, [0x48, 0xff, 0xcb])
    
    # + (43): inc byte [rbx] (FE 03)
    check_and_emit(43, [0xfe, 0x03])
    
    # - (45): dec byte [rbx] (FE 0B)
    check_and_emit(45, [0xfe, 0x0b])
    
    # . (46): write(1, rbx, 1)
    dot_code = [
        0xb8, 0x01, 0x00, 0x00, 0x00,
        0xbf, 0x01, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xde,
        0xba, 0x01, 0x00, 0x00, 0x00,
        0x0f, 0x05
    ]
    check_and_emit(46, dot_code)
    
    # , (44): read(0, rbx, 1)
    comma_code = [
        0xb8, 0x00, 0x00, 0x00, 0x00,
        0xbf, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xde,
        0xba, 0x01, 0x00, 0x00, 0x00,
        0x0f, 0x05
    ]
    check_and_emit(44, comma_code)
    
    # End Loop
    right(2); loop_close(); left(2)
    
    # 4. Exit Code (0)
    emit_bytes([0x48, 0x31, 0xff, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05])
    
    # 5. Padding
    right(4); clear(); inc(total_size); left(4)
    right(7)
    loop_open(); dec(); left(3); dec(); right(3); loop_close()
    left(3)
    loop_open(); right(4); clear(); out(); left(4); dec(); loop_close()

if __name__ == "__main__":
    main()
