import subprocess
from flask import Flask, render_template, request
import os

# class oos:
#     def get(self, *args):
#         return args[6]
def getxxx(a,b,c,d,e):
    os.system(a.b.b) # subprocess.call(os.system(result))不行，没有os.system的函数摘要
    return b

class A:
    def __init__(self):
        self.b=None

req_param = request.form['suggestion']
a=A()
if 1==(3-1):
    a.b="A"
else:
    a.b=req_param
# result=getxxx(c,"B","C","D","E") # 不支持注解@staticmethod， get()能扫到
os.system(a.b) # subprocess.call(os.system(result))不行，没有os.system的函数摘要
