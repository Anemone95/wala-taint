from flask import request
import os

def A():
    src=request.form
    b="A{}".format(src)
    a="a" in src
    os.system(b)
A()
