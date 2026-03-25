#!/usr/bin/env python3
import sys

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python3 bf_to_spaces.py <input.bf>\n")
        sys.exit(1)
    try:
        f = open(sys.argv[1], "r")
        code = f.read()
        f.close()
    except Exception:
        sys.exit(1)
    op_map = {'>': 0, '<': 1, '+': 2, '-': 3, '.': 4, ',': 5, '[': 6, ']': 7}
    for c in code:
        if c in op_map:
            v = op_map[c]
            b2 = (v >> 2) & 1
            b1 = (v >> 1) & 1
            b0 = v & 1
            if b2 == 0:
                sys.stdout.write(" ")
            else:
                sys.stdout.write("\u3000")
            if b1 == 0:
                sys.stdout.write(" ")
            else:
                sys.stdout.write("\u3000")
            if b0 == 0:
                sys.stdout.write(" ")
            else:
                sys.stdout.write("\u3000")

if __name__ == "__main__":
    main()
