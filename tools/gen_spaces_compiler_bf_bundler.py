import sys

ptr = 0

def e(s):
    sys.stdout.write(s)

def move_to(target):
    global ptr
    if target > ptr: e(">" * (target - ptr))
    if target < ptr: e("<" * (ptr - target))
    ptr = target

def build_dummy_pe():
    # 1024バイトの配列 (ヘッダ512バイト + コード512バイト)
    pe = [0] * 1024
    
    # === 1. MS-DOS Header ===
    pe[0], pe[1] = 0x4D, 0x5A # 'MZ'
    pe[0x3C] = 0x40 # e_lfanew (PEヘッダへのオフセット)
    
    # === 2. PE Signature ===
    pe[0x40], pe[0x41] = 0x50, 0x45 # 'PE\0\0'
    
    # === 3. COFF File Header ===
    pe[0x44], pe[0x45] = 0x64, 0x86 # Machine: x86_64
    pe[0x46] = 0x01 # NumberOfSections: 1
    pe[0x54] = 0xF0 # SizeOfOptionalHeader: 240
    pe[0x56] = 0x22 # Characteristics: Executable | LargeAddressAware
    
    # === 4. Optional Header (PE32+) ===
    pe[0x58], pe[0x59] = 0x0B, 0x02 # Magic: PE32+
    
    # 🚀 修正: エントリポイントを 0x1000 (.textセクションの開始位置) に設定
    pe[0x68], pe[0x69] = 0x00, 0x10 # AddressOfEntryPoint: 0x1000
    
    pe[0x74] = 0x40 # ImageBase: 0x400000
    pe[0x78], pe[0x79] = 0x00, 0x10 # SectionAlignment: 0x1000
    pe[0x7C], pe[0x7D] = 0x00, 0x02 # FileAlignment: 0x200
    pe[0x80] = 0x05 # MajorOperatingSystemVersion: 5
    pe[0x88] = 0x05 # MajorSubsystemVersion: 5
    pe[0x90], pe[0x91] = 0x00, 0x20 # SizeOfImage: 0x2000
    pe[0x94], pe[0x95] = 0x00, 0x02 # SizeOfHeaders: 0x200
    pe[0x9C] = 0x03 # Subsystem: 3 (Windows Console)
    pe[0xC4] = 0x10 # NumberOfRvaAndSizes: 16
    
    # === 5. Section Table (.text) ===
    # オフセット 0x148 から
    pe[0x148:0x14D] = [0x2E, 0x74, 0x65, 0x78, 0x74] # Name: '.text'
    pe[0x150], pe[0x151] = 0x00, 0x10 # VirtualSize: 0x1000
    pe[0x154], pe[0x155] = 0x00, 0x10 # VirtualAddress: 0x1000
    pe[0x158], pe[0x159] = 0x00, 0x02 # SizeOfRawData: 0x200
    pe[0x15C], pe[0x15D] = 0x00, 0x02 # PointerToRawData: 0x200 (ファイル内のオフセット 512)
    
    # Characteristics: 0x60000020 (Code | Execute | Read)
    pe[0x16C:0x170] = [0x20, 0x00, 0x00, 0x60] 

    # === 6. Code Section ===
    # ファイルオフセット 0x200 (512番目) にコードを配置
    # アセンブリ:
    # 31 C0 (xor eax, eax) -> 戻り値0
    # C3    (ret)          -> 終了
    pe[0x200], pe[0x201], pe[0x202] = 0x31, 0xC0, 0xC3

    # === バイナリエミッター ===
    for b in pe:
        move_to(20)
        e("[-]")
        if b > 0:
            e("+" * b)
        e(".")

if __name__ == "__main__":
    build_dummy_pe()
