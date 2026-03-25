#!/usr/bin/env python3
import sys

# --- Spaces Dialect ---
S = " "
F = "\u3000"

def emit(s): sys.stdout.write(s + "\n")
def right(n=1): 
    if n > 0: emit((S+S+S)*n)
def left(n=1): 
    if n > 0: emit((S+S+F)*n)
def inc(n=1): 
    if n > 0: emit((S+F+S)*n)
def dec(n=1): 
    if n > 0: emit((S+F+F)*n)
def out(): emit(F+S+S)
def inp(): emit(F+S+F)
def loop_open(): emit(F+F+S)
def loop_close(): emit(F+F+F)
def clear(): loop_open(); dec(); loop_close()

# --- Memory Layout ---
DATA_CELL = 100
CNT_L = 110
CNT_M = 111
CNT_H = 112
OUTPUT_CELL = 200

# Decrement 24-bit Counter (L, M, H)
def dec_counter():
    # Move to L
    right(CNT_L - DATA_CELL)
    
    # Check L
    # Temp L check at +1
    right(1); clear(); inc(); left(1) # Flag=1
    loop_open(); right(1); dec(); left(1); loop_open(); dec(); right(3); inc(); left(3); loop_close(); loop_close() # If L!=0, Flag=0. Move L to +3 temporarily.
    # Restore L
    right(3); loop_open(); left(3); inc(); right(3); dec(); loop_close(); left(3)
    
    # Now Flag(at +1) is 1 if L was 0.
    right(1)
    loop_open()
    dec() # Clear Flag
    left(1); inc(256); right(1) # L = 0 -> 256 (We will dec later, so effectively 255)
    
    # Handle Mid
    right(1) # At M
    # Check M
    right(1); clear(); inc(); left(1) # FlagM=1
    loop_open(); right(1); dec(); left(1); loop_open(); dec(); right(3); inc(); left(3); loop_close(); loop_close()
    right(3); loop_open(); left(3); inc(); right(3); dec(); loop_close(); left(3)
    
    right(1) # At FlagM
    loop_open()
    dec()
    left(1); inc(256); right(1) # M = 0 -> 256
    # Handle High
    right(1); dec(); left(1) # Dec H
    loop_close()
    left(1) # Back to M
    dec() # Dec M
    left(1) # Back to FlagL
    loop_close()
    left(1) # Back to L
    dec() # Dec L
    
    # Return to DATA
    left(CNT_L - DATA_CELL)

# Output byte and update counter
def emit_byte_literal(val):
    # Update Counter
    dec_counter()
    
    # Output
    right(OUTPUT_CELL - DATA_CELL)
    clear()
    if val > 0: inc(val)
    out()
    left(OUTPUT_CELL - DATA_CELL)

def emit_bytes_literal(vals):
    for v in vals:
        emit_byte_literal(v)

def check_and_emit(delta, code_bytes):
    dec(delta)
    
    # Check if DATA_CELL is 0 using Temp 1
    right(1); clear(); inc(); left(1) # Temp1 = 1
    
    # If DATA!=0, Temp1=0.
    loop_open()
    right(1); dec(); left(1) # Temp1=0
    right(2); inc(); left(2) # Move DATA to Temp2
    dec() # Zero DATA to break
    loop_close()
    
    # Restore DATA
    right(2); loop_open(); left(2); inc(); right(2); dec(); loop_close(); left(2)
    
    # Check Temp 1
    right(1)
    loop_open()
    dec() # Clear Temp 1
    left(1)
    emit_bytes_literal(code_bytes)
    right(1)
    loop_close()
    left(1)

def main():
    # 100KB Target Size
    target_file_size = 100000 
    load_addr = 0x400000
    
    def p64(v): return list(v.to_bytes(8, "little"))
    def p32(v): return list(v.to_bytes(4, "little"))

    header = [
        0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0,0,0,0,0,0,0,0,
        0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,
        *p64(load_addr + 120), *p64(64), *p64(0), *p32(0),
        0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    ]
    prog_header = [
        0x01,0x00,0x00,0x00,0x07,0x00,0x00,0x00,
        *p64(0), *p64(load_addr), *p64(load_addr),
        *p64(target_file_size), *p64(0x10000), *p64(0x1000)
    ]
    
    # 1. Init Counter
    # 100000 = 0x01 86 A0
    right(CNT_L); inc(0xA0); left(CNT_L)
    right(CNT_M); inc(0x86); left(CNT_M)
    right(CNT_H); inc(0x01); left(CNT_H)
    
    # 2. Start
    right(DATA_CELL)
    
    # 3. Emit Header
    emit_bytes_literal(header + prog_header)
    emit_bytes_literal([0x48, 0xc7, 0xc3, 0x00, 0x20, 0x40, 0x00])
    
    # 4. Input Loop
    right(5); inc(); loop_open(); left(5)
    inp()
    
    # EOF Check
    loop_open(); right(1); inc(); left(1); dec(); loop_close()
    right(1); loop_open(); left(1); inc(); right(1); dec(); loop_close(); left(1)
    
    right(2); inc(); left(1) # IsEOF=1
    loop_open(); right(1); dec(); left(1); clear(); loop_close()
    
    right(2)
    loop_open()
    left(2)
    
    # EOF Action: Exit Syscall
    emit_bytes_literal([0x48, 0x31, 0xff, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05])
    
    # DYNAMIC PADDING LOOP (Brute Force)
    left(CNT_L - DATA_CELL)
    
    # Emit 120,000 zeros (brute force loops)
    # Loop 120
    right(1); inc(120); loop_open()
    # Loop 100
    right(1); inc(100); loop_open()
    # Loop 10
    right(1); inc(10); loop_open()
    # Emit 0
    left(3); emit_byte_literal(0); right(3)
    dec(); loop_close()
    left(1); dec(); loop_close()
    left(1); dec(); loop_close()
    left(1)

    # Kill Flags
    right(2); dec(); left(2) # IsEOF
    right(5); dec(); left(5) # MainFlag
    dec() # Kill Loop
    loop_close()
    left(2)
    
    # Dense Switch
    check_and_emit(43, [0xfe, 0x03])
    check_and_emit(1, [0xb8, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xde, 0xba, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05])
    check_and_emit(1, [0xfe, 0x0b])
    check_and_emit(1, [0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0xde, 0xba, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05])
    check_and_emit(14, [0x48, 0xff, 0xcb])
    check_and_emit(2, [0x48, 0xff, 0xc3])
    
    dec(29); dec(2)
    clear()
    right(5); loop_close()

if __name__ == "__main__":
    main()
