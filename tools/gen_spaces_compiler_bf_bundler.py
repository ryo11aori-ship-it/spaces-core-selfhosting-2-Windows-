import sys

ptr = 0

def e(s):
    sys.stdout.write(s)

def move_to(target):
    global ptr
    if target > ptr: e(">" * (target - ptr))
    if target < ptr: e("<" * (ptr - target))
    ptr = target

def set_val(addr, val):
    move_to(addr); e("[-]"); e("+" * val)

def sub_val(addr, val):
    move_to(addr); e("-" * val)

def copy(src, dst, tmp):
    move_to(tmp); e("[-]"); move_to(dst); e("[-]")
    move_to(src); e("["); move_to(dst); e("+"); move_to(tmp); e("+"); move_to(src); e("-"); e("]")
    move_to(tmp); e("["); move_to(src); e("+"); move_to(tmp); e("-"); e("]")

def if_zero(var_addr, flag_addr, callback):
    set_val(flag_addr, 1)
    move_to(var_addr); e("["); set_val(flag_addr, 0); move_to(var_addr); e("[-]"); e("]")
    move_to(flag_addr); e("[")
    callback()
    set_val(flag_addr, 0); e("]")

def shift_and_add(buf_addr, val_addr, tmp1, tmp2):
    move_to(tmp1); e("[-]")
    move_to(buf_addr); e("["); move_to(tmp1); e("+"); move_to(buf_addr); e("-"); e("]")
    move_to(tmp1); e("["); move_to(buf_addr); e("++"); move_to(tmp1); e("-"); e("]")
    copy(val_addr, tmp1, tmp2)
    move_to(tmp1); e("["); move_to(buf_addr); e("+"); move_to(tmp1); e("-"); e("]")

def emit_header():
    # === 1. PEヘッダの構築 ===
    pe = bytearray(1536)
    def w32(offset, val): pe[offset:offset+4] = val.to_bytes(4, 'little')
    def w64(offset, val): pe[offset:offset+8] = val.to_bytes(8, 'little')
    def w16(offset, val): pe[offset:offset+2] = val.to_bytes(2, 'little')
    def wstr(offset, s):  pe[offset:offset+len(s)] = s.encode('ascii')

    wstr(0x00, "MZ"); w32(0x3C, 0x40)
    wstr(0x40, "PE\0\0"); w16(0x44, 0x8664); w16(0x46, 4) 
    w16(0x54, 240); w16(0x56, 0x0022)
    w16(0x58, 0x020B); w32(0x68, 0x1000); w32(0x74, 0x400000)
    w32(0x78, 0x1000); w32(0x7C, 0x200)
    w16(0x80, 5); w16(0x88, 5)
    
    # 🚀 修正: SizeOfImage を正しい 0x203000 に設定！ (Wineの門前払いを回避)
    w32(0x90, 0x203000); w32(0x94, 0x200); w16(0x9C, 3); w32(0xC4, 16)
    w32(0xD0, 0x2000); w32(0xD4, 0x28)

    wstr(0x148, ".text"); w32(0x150, 0x1000); w32(0x154, 0x1000)
    w32(0x158, 0x200); w32(0x15C, 0x200); w32(0x16C, 0x60000020)
    
    wstr(0x170, ".idata"); w32(0x178, 0x1000); w32(0x17C, 0x2000)
    w32(0x180, 0x200); w32(0x184, 0x400); w32(0x194, 0xC0000040)
    
    wstr(0x198, ".bss"); w32(0x1A0, 0x100000); w32(0x1A4, 0x3000)
    w32(0x1BC, 0xC0000080)
    
    wstr(0x1C0, ".space"); w32(0x1C8, 0x100000); w32(0x1CC, 0x103000)
    w32(0x1D0, 0x100000); w32(0x1D4, 0x600); w32(0x1E4, 0x40000040)

    # IAT
    w32(0x400, 0x2028); w32(0x40C, 0x2050); w32(0x410, 0x2060)
    w64(0x428, 0x2080); w64(0x430, 0x20A0); w64(0x438, 0x20C0)
    wstr(0x450, "msvcrt.dll\0")
    w64(0x460, 0x2080); w64(0x468, 0x20A0); w64(0x470, 0x20C0)
    wstr(0x482, "putchar\0"); wstr(0x4A2, "getchar\0"); wstr(0x4C2, "exit\0")

    # === 2. x86_64 ミニ・アセンブラ ===
    code = bytearray()
    labels = {}; fixups = []
    
    def asm(*bs): code.extend(bs)
    def label(n): labels[n] = len(code)
    def jmp_rel8(op, n):
        asm(*op); fixups.append((len(code), n, 1)); asm(0)
    def jmp_rel32(op, n):
        asm(*op); fixups.append((len(code), n, 4)); asm(0,0,0,0)
    def call_iat(rva):
        rip_rva = 0x1000 + len(code) + 6
        offset = (rva - rip_rva) & 0xFFFFFFFF
        asm(0xFF, 0x15, *offset.to_bytes(4, 'little'))
    
    # 🚀 修正: lea命令を正しく生成する専用関数を作成
    def lea_reg(prefix, rva):
        rip_rva = 0x1000 + len(code) + 7
        offset = (rva - rip_rva) & 0xFFFFFFFF
        asm(*prefix, *offset.to_bytes(4, 'little'))

    # r12 = .bss / r13 = .space
    lea_reg([0x4C, 0x8D, 0x25], 0x3000)   # lea r12, [rip+...]
    lea_reg([0x4C, 0x8D, 0x2D], 0x103000) # lea r13, [rip+...]
    asm(0x48, 0x83, 0xEC, 0x28) # sub rsp, 40

    label('loop')
    asm(0x41, 0x0F, 0xB6, 0x45, 0x00) # movzx eax, byte [r13]
    asm(0x49, 0xFF, 0xC5)             # inc r13
    asm(0x84, 0xC0)                   # test al, al (EOF=0)
    jmp_rel32([0x0F, 0x84], 'exit')

    # オペコード 1-8
    asm(0x3C, 0x01); jmp_rel8([0x75], 'c2'); asm(0x49, 0xFF, 0xC4); jmp_rel32([0xE9], 'loop')
    label('c2')
    asm(0x3C, 0x02); jmp_rel8([0x75], 'c3'); asm(0x49, 0xFF, 0xCC); jmp_rel32([0xE9], 'loop')
    label('c3')
    asm(0x3C, 0x03); jmp_rel8([0x75], 'c4'); asm(0x41, 0xFE, 0x04, 0x24); jmp_rel32([0xE9], 'loop')
    label('c4')
    asm(0x3C, 0x04); jmp_rel8([0x75], 'c5'); asm(0x41, 0xFE, 0x0C, 0x24); jmp_rel32([0xE9], 'loop')
    label('c5')
    asm(0x3C, 0x05); jmp_rel8([0x75], 'c6'); asm(0x41, 0x0F, 0xB6, 0x0C, 0x24) # putchar
    call_iat(0x2060); jmp_rel32([0xE9], 'loop')
    label('c6')
    asm(0x3C, 0x06); jmp_rel8([0x75], 'c7'); call_iat(0x2068) # getchar
    asm(0x83, 0xF8, 0xFF); jmp_rel8([0x75], 's_c'); asm(0x31, 0xC0)
    label('s_c'); asm(0x41, 0x88, 0x04, 0x24); jmp_rel32([0xE9], 'loop')
    
    # ループ [ と ]
    label('c7')
    asm(0x3C, 0x07); jmp_rel8([0x75], 'c8')
    asm(0x41, 0x80, 0x3C, 0x24, 0x00); jmp_rel32([0x0F, 0x85], 'loop')
    asm(0xBA, 0x01, 0x00, 0x00, 0x00)
    label('f_r')
    asm(0x41, 0x0F, 0xB6, 0x45, 0x00); asm(0x49, 0xFF, 0xC5)
    asm(0x3C, 0x07); jmp_rel8([0x75], 'n_l'); asm(0xFF, 0xC2)
    label('n_l')
    asm(0x3C, 0x08); jmp_rel8([0x75], 'e_r'); asm(0xFF, 0xCA)
    label('e_r'); asm(0x85, 0xD2); jmp_rel32([0x0F, 0x85], 'f_r'); jmp_rel32([0xE9], 'loop')
    
    label('c8')
    asm(0x3C, 0x08); jmp_rel32([0x0F, 0x85], 'loop')
    asm(0x41, 0x80, 0x3C, 0x24, 0x00); jmp_rel32([0x0F, 0x84], 'loop')
    asm(0xBA, 0x01, 0x00, 0x00, 0x00); asm(0x49, 0x83, 0xED, 0x02)
    label('f_l')
    asm(0x41, 0x0F, 0xB6, 0x45, 0x00); asm(0x49, 0xFF, 0xCD)
    asm(0x3C, 0x08); jmp_rel8([0x75], 'n_r'); asm(0xFF, 0xC2)
    label('n_r')
    asm(0x3C, 0x07); jmp_rel8([0x75], 'e_l'); asm(0xFF, 0xCA)
    label('e_l'); asm(0x85, 0xD2); jmp_rel32([0x0F, 0x85], 'f_l')
    asm(0x49, 0x83, 0xC5, 0x02); jmp_rel32([0xE9], 'loop')

    label('exit')
    asm(0x31, 0xC9); call_iat(0x2070) # exit(0)

    for offset, name, size in fixups:
        target = labels[name]
        rel = target - (offset + size)
        code[offset:offset+size] = rel.to_bytes(size, 'little', signed=True)

    pe[0x200:0x200+len(code)] = bytes(code)

    curr = 0
    for b in pe:
        diff = (b - curr) % 256
        if diff > 128: diff -= 256
        if diff > 0: e("+" * diff)
        elif diff < 0: e("-" * (-diff))
        e(".")
        curr = b

def build_parser():
    emit_header()
    set_val(2, 0); set_val(3, 0)
    move_to(1); e(","); e("[")
    set_val(4, 0); set_val(5, 0)
    copy(1, 6, 7); sub_val(6, 32)
    def on_space():
        set_val(4, 1); set_val(5, 0)
    if_zero(6, 8, on_space)
    copy(1, 6, 7); sub_val(6, 227)
    def on_full():
        e("[-],[-],")
        set_val(4, 1); set_val(5, 1)
    if_zero(6, 8, on_full)
    move_to(4); e("[")
    shift_and_add(3, 5, 6, 7)
    move_to(2); e("+")
    copy(2, 6, 7); sub_val(6, 3)
    def on_3bits():
        move_to(3); e("+.") 
        set_val(2, 0); set_val(3, 0)
    if_zero(6, 8, on_3bits)
    set_val(4, 0); e("]")
    move_to(1); e("[-],"); e("]")

if __name__ == "__main__":
    build_parser()
