from flask import request
import os


# class oos:
#     def get(self, *args):
#         return args[6]
def getxxx(a,b,c,d,e):
    f=a.b
    os.system(f.b) # subprocess.call(os.system(result))不行，没有os.system的函数摘要
class A:
    def __init__(self):
        self.b=None

req_param = request.form['suggestion']
a=A()
a.b=req_param
c=A()
c.b=a
# result=getxxx(c,"B","C","D","E") # 不支持注解@staticmethod， get()能扫到
ret=getxxx(c, "b", "c", "d", "e") # subprocess.call(os.system(result))不行，没有os.system的函数摘要
