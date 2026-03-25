import sys
import os

def main():
    if len(sys.argv) < 2: return
    
    arg = sys.argv[1]
    code = ""

    # 引数がファイルとして存在すれば読み込む、なければそのままコードとして扱う
    if os.path.isfile(arg):
        with open(arg, 'r', encoding='utf-8') as f:
            code = f.read()
    else:
        code = arg

    S = " "
    F = "\u3000"
    mapping = {
        '>': S+S+S, '<': S+S+F,
        '+': S+F+S, '-': S+F+F,
        '.': F+S+S, ',': F+S+F,
        '[': F+F+S, ']': F+F+F
    }
    
    res = ""
    for c in code:
        if c in mapping: res += mapping[c]
    
    # 最後に改行を入れない（バイナリ一致検証のため）
    print(res, end='')

if __name__ == "__main__":
    main()
