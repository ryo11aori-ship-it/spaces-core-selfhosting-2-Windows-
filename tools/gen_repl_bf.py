import sys

class BF:
    def __init__(self):
        self.code = ""
        self.p = 0
    def go(self, n):
        if n > self.p: self.code += ">" * (n - self.p)
        elif n < self.p: self.code += "<" * (self.p - n)
        self.p = n
    def clear(self, n): self.go(n); self.code += "[-]"
    def add(self, n, v): self.go(n); self.code += "+" * v
    def sub(self, n, v): self.go(n); self.code += "-" * v
    def copy(self, src, dst, tmp):
        self.clear(dst); self.clear(tmp)
        self.go(src); self.code += "["
        self.go(dst); self.code += "+"
        self.go(tmp); self.code += "+"
        self.go(src); self.code += "-]"
        self.go(tmp); self.code += "["
        self.go(src); self.code += "+"
        self.go(tmp); self.code += "-]"
    def if_zero(self, var, flag, cb):
        self.clear(flag); self.add(flag, 1)
        self.go(var); self.code += "["
        self.clear(flag); self.clear(var); self.code += "]"
        self.go(flag); self.code += "["
        cb(); self.clear(flag); self.code += "]"
    def if_not_zero(self, var, cb):
        self.go(var); self.code += "["
        cb(); self.clear(var); self.code += "]"

bf = BF()

# === メモリレイアウト ===
# 0:b(ビット数), 1:a(オペコード), 2:c(入力文字), 3:bit_val, 4:is_space, 5..7:temps
# 8:HomeMarker(0), 9:Dummy(0), 10:TapeMarker(0=Head), 11:TapeData...

def print_prompt():
    bf.add(5, 62); bf.go(5); bf.code += "."; bf.clear(5)
    bf.add(5, 32); bf.go(5); bf.code += "."; bf.clear(5)

def execute_opcode():
    # 0 (>)
    bf.copy(1, 5, 6)
    def op_0():
        bf.go(8); bf.code += ">>[>>]"     # Find Head
        bf.code += "+ >> [-]"             # Move Right
        bf.code += "<<[<<]"               # Return Home
    bf.if_zero(5, 7, op_0)

    # 1 (<)
    bf.copy(1, 5, 6); bf.sub(5, 1)
    def op_1():
        bf.go(8); bf.code += ">>[>>]"
        bf.code += "+ << [-]"             # Move Left
        bf.code += "<<[<<]"
    bf.if_zero(5, 7, op_1)

    # 2 (+)
    bf.copy(1, 5, 6); bf.sub(5, 2)
    def op_2():
        bf.go(8); bf.code += ">>[>>]"
        bf.code += ">+<"                  # Data + 1
        bf.code += "<<[<<]"
    bf.if_zero(5, 7, op_2)

    # 3 (-)
    bf.copy(1, 5, 6); bf.sub(5, 3)
    def op_3():
        bf.go(8); bf.code += ">>[>>]"
        bf.code += ">-<"                  # Data - 1
        bf.code += "<<[<<]"
    bf.if_zero(5, 7, op_3)

    # 4 (.)
    bf.copy(1, 5, 6); bf.sub(5, 4)
    def op_4():
        bf.go(8); bf.code += ">>[>>]"
        bf.code += ">.<"                  # Print
        bf.code += "<<[<<]"
    bf.if_zero(5, 7, op_4)

    # 5 (,)
    bf.copy(1, 5, 6); bf.sub(5, 5)
    def op_5():
        bf.go(8); bf.code += ">>[>>]"
        bf.code += ">,<"                  # Read
        bf.code += "<<[<<]"
    bf.if_zero(5, 7, op_5)

# 初期プロンプト
print_prompt()

# REPL無限ループ
bf.add(20, 1)
bf.go(20); bf.code += "["

bf.go(2); bf.code += "," # Read char

# Newlineチェック (10)
bf.copy(2, 5, 6); bf.sub(5, 10)
def on_newline():
    print_prompt()
bf.if_zero(5, 7, on_newline)

# Spaces解読ロジック
bf.clear(3); bf.clear(4)

# 半角スペース (32)
bf.copy(2, 5, 6); bf.sub(5, 32)
def on_half():
    bf.clear(3)
    bf.clear(4); bf.add(4, 1)
bf.if_zero(5, 7, on_half)

# 全角スペース (227)
bf.copy(2, 5, 6); bf.sub(5, 227)
def on_full():
    bf.go(2); bf.code += ",," # 続く2バイトを破棄
    bf.add(3, 1)
    bf.add(4, 1)
bf.if_zero(5, 7, on_full)

# スペース処理
def process_space():
    # a = a * 2 + bit_val
    bf.clear(5)
    bf.go(1); bf.code += "["; bf.go(5); bf.code += "++"; bf.go(1); bf.code += "-]"
    bf.go(5); bf.code += "["; bf.go(1); bf.code += "+"; bf.go(5); bf.code += "-]"
    bf.go(3); bf.code += "["; bf.go(1); bf.code += "+"; bf.go(3); bf.code += "-]"
    
    # b++
    bf.add(0, 1)
    
    # if b == 3 -> コマンド実行
    bf.copy(0, 5, 6); bf.sub(5, 3)
    def on_ready():
        execute_opcode()
        bf.clear(0); bf.clear(1)
    bf.if_zero(5, 7, on_ready)

bf.if_not_zero(4, process_space)

bf.go(20); bf.code += "]"

print(bf.code)
