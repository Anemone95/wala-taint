import subprocess
from flask import Flask, render_template, request
import os

# class oos:
#     def get(self, *args):
#         return args[6]
def thread(sys,b,c,d,e):
    os.system(b) # subprocess.call(os.system(result))不行，没有os.system的函数摘要
    # return b # return b+1,c

class A:
    def __init__(self):
        self.b=None

req_param = request.form['suggestion']
a=A()
a.b=req_param
ssss=os.system
# result=getxxx(c,"B","C","D","E") # 不支持注解@staticmethod， get()能扫到
thread(ssss,req_param)
# ret=thread(system, req_param, "c", "d", "e") # subprocess.call(os.system(result))不行，没有os.system的函数摘要
