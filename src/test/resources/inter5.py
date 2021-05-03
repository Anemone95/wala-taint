from flask import request
import os


def thread(sys, b, c, d, e):
    sys(b)  # subprocess.call(os.system(result))不行，没有os.system的函数摘要
    # return b # return b+1,c


def safe(sys, b, c, d, e):
    print(b)  # subprocess.call(os.system(result))不行，没有os.system的函数摘要


class A:
    def __init__(self):
        self.b = None


req_param = request.form['suggestion']
req_param += "A"
func = os.system
a = A()
a.b = func
l = lambda a: a.b

li = [thread, a, "SSS"]
di = {"li": []}
di["li"] = li
di2 = di
di2["li"][0](l(a), req_param, "c", "d", "e")
