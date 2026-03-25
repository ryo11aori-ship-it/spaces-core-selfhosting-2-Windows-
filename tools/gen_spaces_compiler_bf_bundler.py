import sys

def build_dummy_pe():
    # 3セクター分 (1536バイト) の空のバイナリ配列
    pe = bytearray(1536)

    def w32(offset, val): pe[offset:offset+4] = val.to_bytes(4, 'little')
    def w64(offset, val): pe[offset:offset+8] = val.to_bytes(8, 'little')
    def w16(offset, val): pe[offset:offset+2] = val.to_bytes(2, 'little')
    def wstr(offset, s):  pe[offset:offset+len(s)] = s.encode('ascii')

    # === 1. MS-DOS Header ===
    wstr(0x00, "MZ")
    w32(0x3C, 0x40)

    # === 2. COFF Header ===
    wstr(0x40, "PE\0\0")
    w16(0x44, 0x8664) # Machine: x86_64
    w16(0x46, 3)      # Number of Sections (.text, .idata, .bss)
    w16(0x54, 240)    # SizeOfOptionalHeader
    w16(0x56, 0x0022) # Characteristics (Executable | LargeAddressAware)

    # === 3. Optional Header ===
    w16(0x58, 0x020B) # Magic: PE32+
    w32(0x68, 0x1000) # AddressOfEntryPoint
    w32(0x74, 0x400000) # ImageBase
    w32(0x78, 0x1000) # SectionAlignment
    w32(0x7C, 0x200)  # FileAlignment
    w16(0x80, 5); w16(0x88, 5) # OS Version
    w32(0x90, 0x103000) # SizeOfImage
    w32(0x94, 0x200)  # SizeOfHeaders
    w16(0x9C, 3)      # Subsystem (Windows Console)
    w32(0xC4, 16)     # NumberOfRvaAndSizes

    # Import Directory RVA & Size
    w32(0xD0, 0x2000); w32(0xD4, 0x28)
    
    # IAT Directory RVA & Size (念のため明示的に指定)
    w32(0x118, 0x2060); w32(0x11C, 0x18)

    # === 4. Section Table ===
    wstr(0x148, ".text")
    w32(0x150, 0x1000); w32(0x154, 0x1000)
    w32(0x158, 0x200);  w32(0x15C, 0x200)
    w32(0x16C, 0x60000020) # Code, Execute, Read

    wstr(0x170, ".idata")
    w32(0x178, 0x1000); w32(0x17C, 0x2000)
    w32(0x180, 0x200);  w32(0x184, 0x400)
    w32(0x194, 0xC0000040) # Init Data, Read, Write

    # .bss (1MBテープハック)
    wstr(0x198, ".bss")
    w32(0x1A0, 0x100000); w32(0x1A4, 0x3000)
    w32(0x1BC, 0xC0000080) # Uninit Data, Read, Write

    # === 5. Code Section (.text) ===
    # 🚀 msvcrt.dll の putchar('H') を呼ぶ究極にシンプルなアセンブリ
    code = [
        0x48, 0x83, 0xEC, 0x28,             # sub rsp, 40 (Shadow Spaceの確保)
        
        0xB9, 0x48, 0x00, 0x00, 0x00,       # mov ecx, 72 ('H')
        0xFF, 0x15, 0x51, 0x10, 0x00, 0x00, # call [rip+0x1051] -> putchar
        
        0x31, 0xC9,                         # xor ecx, ecx (戻り値 0)
        0xFF, 0x15, 0x51, 0x10, 0x00, 0x00  # call [rip+0x1051] -> exit
    ]
    pe[0x200:0x200+len(code)] = bytes(code)

    # === 6. IAT Section (.idata) ===
    w32(0x400, 0x2028) # INT RVA
    w32(0x40C, 0x2050) # Name RVA
    w32(0x410, 0x2060) # IAT RVA
    
    # INT (Import Name Table)
    w64(0x428, 0x2080); w64(0x430, 0x20A0)
    # Target DLL Name
    wstr(0x450, "msvcrt.dll\0")
    # IAT (Import Address Table)
    w64(0x460, 0x2080); w64(0x468, 0x20A0)
    # Hint & Names
    wstr(0x482, "putchar\0"); wstr(0x4A2, "exit\0")

    # === 7. 超高速BFエミッター ===
    curr = 0
    for b in pe:
        diff = (b - curr) % 256
        if diff > 128: diff -= 256
        
        if diff > 0: sys.stdout.write("+" * diff)
        elif diff < 0: sys.stdout.write("-" * (-diff))
        sys.stdout.write(".")
        curr = b

if __name__ == "__main__":
    build_dummy_pe()
