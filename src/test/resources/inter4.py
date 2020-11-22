import subprocess
from flask import Flask, render_template, request
import os

# class oos:
#     def get(self, *args):
#         return args[6]
def thread(sys,b,c,d,e):
    sys(b) # subprocess.call(os.system(result))不行，没有os.system的函数摘要
    # return b # return b+1,c

class A:
    def __init__(self):
        self.b=None

req_param = request.form['suggestion']
func=os.system
thread(func,req_param, "c", "d", "e")
# ret=thread(system, req_param, "c", "d", "e") # subprocess.call(os.system(result))不行，没有os.system的函数摘要
