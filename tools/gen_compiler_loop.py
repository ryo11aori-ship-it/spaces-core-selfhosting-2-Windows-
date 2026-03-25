#!/usr/bin/env python3
# tools/gen_compiler_loop.py
# Level 1.0: The Real Loop Compiler (Fixed Memory Management)

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
# C2: Main Loop Flag (1 = Run, 0 = Stop)
# C3: Non-destructive Copy Backup
# C4: Padding Counter
# C7: Output Byte Counter
# C8: Output Buffer (Temporary for out)

def emit_byte_tracked(val):
    # C8を使用して1バイト出力し、C7をインクリメントする
    # C0に戻る
    right(8); clear()
    if val > 0: inc(val)
    out(); clear(); left(8)
    right(7); inc(); left(7)

def emit_bytes(vals):
    for v in vals: emit_byte_tracked(v)

def copy_c0_to_c1():
    # C3をバックアップに使って、C0をC1に非破壊コピーする
    # C0で開始し、C0で終わる
    right(1); clear(); right(2); clear(); left(3) # C1, C3をクリア
    loop_open()
    dec()
    right(1); inc() # C1++
    right(2); inc() # C3++
    left(3)
    loop_close()
    # C3からC0を復元
    right(3)
    loop_open()
    dec(); left(3); inc(); right(3)
    loop_close()
    left(3)

def main():
    total_size = 300
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
        *p64(total_size), *p64(total_size), *p64(0x1000)
    ]
    
    # 1. ELF Header出力
    emit_bytes(header + prog_header)
    emit_bytes([0x48, 0x31, 0xdb]) # xor rbx, rbx (初期化)
    
    # 2. メインループ準備
    # C2 (Flag) = 1
    right(2); clear(); inc(); left(2) 
    
    # Loop [ while C2 != 0 ]
    right(2)
    loop_open()
    left(2) # C0に移動
    
    # --- Inside Loop ---
    # (1) Read Char
    clear(); inp()
    
    # (2) EOFチェック (C0 == 0?)
    copy_c0_to_c1()
    # C1が0ならC3=1にする判定
    right(3); clear(); inc(); left(2) # C3=1, at C1
    loop_open(); right(2); clear(); left(2); clear(); loop_close()
    
    # C3が1ならEOF -> C2を0にする
    right(2)
    loop_open()
    left(1); clear(); right(1) # C2=0
    clear() # C3=0
    loop_close()
    left(3) # Back to C0
    
    # (3) '+' (43) チェック
    copy_c0_to_c1()
    right(1); dec(43) # C1 -= 43
    right(2); clear(); inc(); left(2) # C3=1
    loop_open(); right(2); clear(); left(2); clear(); loop_close()
    
    # C3が1なら一致: inc rbx を書き出す
    right(2)
    loop_open()
    left(3) # C0
    emit_byte_tracked(0x48); emit_byte_tracked(0xff); emit_byte_tracked(0xc3)
    right(3); clear(); loop_close()
    left(3) # C0

    # (4) '-' (45) チェック
    copy_c0_to_c1()
    right(1); dec(45)
    right(2); clear(); inc(); left(2)
    loop_open(); right(2); clear(); left(2); clear(); loop_close()
    
    right(2)
    loop_open()
    left(3)
    emit_byte_tracked(0x48); emit_byte_tracked(0xff); emit_byte_tracked(0xcb)
    right(3); clear(); loop_close()
    left(3) # C0
    
    # --- End Loop ---
    right(2); loop_close(); left(2) # C2をチェックして戻る
    
    # 3. 終了処理 (Exit syscall)
    emit_bytes([0x89, 0xdf, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05])
    
    # 4. パディング (300バイトまで埋める)
    # C4 = 300
    right(4); clear(); inc(300); left(4)
    # C4 = C4 - C7
    right(7)
    loop_open()
    dec(); left(3); dec(); right(3) # C7を減らしながらC4を減らす
    loop_close()
    
    # C4の回数分だけ0を出力
    left(3) # at C4
    loop_open()
    right(4); clear(); out(); left(4) # C8を使用して0出力
    dec()
    loop_close()

if __name__ == "__main__":
    main()
