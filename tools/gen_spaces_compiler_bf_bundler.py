import sys

def build_dummy_pe():
    # 3セクター分 (1536バイト) の空のバイナリ配列
    pe = bytearray(1536)

    # バイナリ書き込み用のヘルパー関数
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
    w32(0x68, 0x1000) # AddressOfEntryPoint (RVA to .text)
    w32(0x74, 0x400000) # ImageBase
    w32(0x78, 0x1000) # SectionAlignment
    w32(0x7C, 0x200)  # FileAlignment
    w16(0x80, 5)      # MajorOperatingSystemVersion
    w16(0x88, 5)      # MajorSubsystemVersion
    w32(0x90, 0x103000) # SizeOfImage (Headers + .text + .idata + 1MB .bss)
    w32(0x94, 0x200)  # SizeOfHeaders
    w16(0x9C, 3)      # Subsystem (Windows Console)
    w32(0xC4, 16)     # NumberOfRvaAndSizes

    # Data Directories (Import Directory)
    w32(0xD0, 0x2000) # Import Directory RVA
    w32(0xD4, 0x28)   # Import Directory Size

    # === 4. Section Table ===
    # .text (コード領域)
    wstr(0x148, ".text")
    w32(0x150, 0x1000) # VirtualSize
    w32(0x154, 0x1000) # VirtualAddress
    w32(0x158, 0x200)  # SizeOfRawData
    w32(0x15C, 0x200)  # PointerToRawData
    w32(0x16C, 0x60000020) # Characteristics (Code, Execute, Read)

    # .idata (Windows API 解決領域)
    wstr(0x170, ".idata")
    w32(0x178, 0x1000)
    w32(0x17C, 0x2000)
    w32(0x180, 0x200)
    w32(0x184, 0x400)
    w32(0x194, 0x40000040) # Characteristics (Initialized Data, Read)

    # .bss (1MBのテープ確保ハック！)
    wstr(0x198, ".bss")
    w32(0x1A0, 0x100000) # VirtualSize: 1MB
    w32(0x1A4, 0x3000)   # VirtualAddress
    w32(0x1A8, 0)        # SizeOfRawData: 0 (ファイルサイズを消費しない！)
    w32(0x1AC, 0)        # PointerToRawData: 0
    w32(0x1BC, 0xC0000080) # Characteristics (Uninitialized Data, Read, Write)

    # === 5. Code Section (.text) ===
    # IATを使って "H" を出力するx86_64アセンブリ
    code = [
        0x48, 0x83, 0xEC, 0x28,                         # sub rsp, 40 (Shadow Space確保)
        
        # GetStdHandle(-11) -> StdOutハンドルの取得
        0x48, 0xC7, 0xC1, 0xF5, 0xFF, 0xFF, 0xFF,       # mov rcx, -11
        0x48, 0xC7, 0xC0, 0x60, 0x20, 0x40, 0x00,       # mov rax, 0x402060 (IAT: GetStdHandle)
        0xFF, 0x10,                                     # call [rax]
        0x48, 0x89, 0xC3,                               # mov rbx, rax (ハンドルを保存)

        # WriteFile(hConsole, buffer, 1, &written, NULL)
        0xC6, 0x44, 0x24, 0x30, 0x48,                   # mov byte ptr [rsp+48], 'H'
        0x48, 0x89, 0xD1,                               # mov rcx, rbx
        0x48, 0x8D, 0x54, 0x24, 0x30,                   # lea rdx, [rsp+48]
        0x49, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,       # mov r8, 1
        0x4C, 0x8D, 0x4C, 0x24, 0x38,                   # lea r9, [rsp+56]
        0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, # mov qword ptr [rsp+32], 0
        0x48, 0xC7, 0xC0, 0x68, 0x20, 0x40, 0x00,       # mov rax, 0x402068 (IAT: WriteFile)
        0xFF, 0x10,                                     # call [rax]

        # ExitProcess(0)
        0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,       # mov rcx, 0
        0x48, 0xC7, 0xC0, 0x70, 0x20, 0x40, 0x00,       # mov rax, 0x402070 (IAT: ExitProcess)
        0xFF, 0x10                                      # call [rax]
    ]
    pe[0x200:0x200+len(code)] = bytes(code)

    # === 6. IAT Section (.idata) ===
    w32(0x400, 0x2028) # INT RVA
    w32(0x40C, 0x2050) # Name RVA ("KERNEL32.dll")
    w32(0x410, 0x2060) # IAT RVA
    # INT
    w64(0x428, 0x2080); w64(0x430, 0x20A0); w64(0x438, 0x20C0)
    # Name
    wstr(0x450, "KERNEL32.dll\0")
    # IAT
    w64(0x460, 0x2080); w64(0x468, 0x20A0); w64(0x470, 0x20C0)
    # Hint/Names
    wstr(0x482, "GetStdHandle\0"); wstr(0x4A2, "WriteFile\0"); wstr(0x4C2, "ExitProcess\0")

    # === 7. 究極の超高速BFエミッター ===
    # 差分だけを計算して1つのセルだけで全バイナリを出力するハック
    curr = 0
    for b in pe:
        diff = b - curr
        if diff > 0: sys.stdout.write("+" * diff)
        elif diff < 0: sys.stdout.write("-" * (-diff))
        sys.stdout.write(".")
        curr = b

if __name__ == "__main__":
    build_dummy_pe()
