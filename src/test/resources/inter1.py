from flask import request
import os


# class oos:
#     def get(self, *args):
#         return args[6]
def getxxx(a,b,c,d,e):
    return b # return b+1,c

class A:
    def __init__(self):
        self.b=None

req_param = request.form['suggestion']
a=A()
a.b=req_param
c=A()
c.b=a
ret=getxxx("A", c, "c", "d", "e") # subprocess.call(os.system(result))不行，没有os.system的函数摘要
os.system(ret.b.b)
