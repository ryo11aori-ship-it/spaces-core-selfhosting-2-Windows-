import sys
class VM:
 def __init__(s):
  s.c=""
  s.p=0
 def g(s,n):
  if n>s.p:s.c+=">"*(n-s.p)
  elif n<s.p:s.c+="<"*(s.p-n)
  s.p=n
 def z(s,n):
  s.g(n);s.c+="[-]"
 def a(s,n,v):
  s.g(n);s.c+="+"*v
 def d(s,n,v):
  s.g(n);s.c+="-"*v
 def cp(s,src,dst,t):
  s.z(dst);s.z(t);s.g(src);s.c+="["
  s.g(dst);s.c+="+"
  s.g(t);s.c+="+"
  s.g(src);s.c+="-]"
  s.g(t);s.c+="["
  s.g(src);s.c+="+"
  s.g(t);s.c+="-]"
 def jz(s,v,f,cb):
  s.z(f);s.a(f,1);s.g(v);s.c+="["
  s.z(f);s.z(v);s.c+="]";s.g(f);s.c+="["
  cb();s.z(f);s.c+="]"
 def jnz(s,v,cb):
  s.g(v);s.c+="["
  cb();s.z(v);s.c+="]"
v=VM()
# Mem: 0:bits 1:op 2:char 3:bit_val 4:is_space 5..9:tmp
# 10:CodeBase 1000:DataBase
def pr():
 v.a(5,62);v.g(5);v.c+=".";v.z(5)
 v.a(5,32);v.g(5);v.c+=".";v.z(5)
pr()
v.a(2000,1)
v.g(2000);v.c+="["
v.g(10);v.c+="[[-]>]<<[<]" # Clear old code
v.g(2);v.c+="," # Read
v.cp(2,5,6);v.d(5,10)
def nl():
 v.g(10);v.c+=">[[->+<]>]<<[<]" # Shift to execute
 # VM Execution Logic
 v.g(1000);v.c+=">>[>>]"
 v.c+="<<[<<]"
 pr()
v.jz(5,7,nl)
v.z(3);v.z(4)
v.cp(2,5,6);v.d(5,32)
def sh():
 v.z(3);v.z(4);v.a(4,1)
v.jz(5,7,sh)
v.cp(2,5,6);v.d(5,227)
def sf():
 v.g(2);v.c+=",,"
 v.a(3,1);v.a(4,1)
v.jz(5,7,sf)
def ps():
 v.z(5);v.g(1);v.c+="["
 v.g(5);v.c+="++"
 v.g(1);v.c+="-]"
 v.g(5);v.c+="["
 v.g(1);v.c+="+"
 v.g(5);v.c+="-]"
 v.g(3);v.c+="["
 v.g(1);v.c+="+"
 v.g(3);v.c+="-]"
 v.a(0,1)
 v.cp(0,5,6);v.d(5,3)
 def rd():
  v.g(10);v.c+=">[>]<" # find end of code
  v.c+=">[-]+<" # append op
  v.c+="[<]>"
  v.z(0);v.z(1)
 v.jz(5,7,rd)
v.jnz(4,ps)
v.g(2000);v.c+="]"
sys.stdout.write(v.c)
