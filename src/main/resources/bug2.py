from flask import request
import subprocess

src=request.form
# b="A{}".format(src)
# a="a" in src
p = subprocess.Popen(src, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
# p = subprocess.Popen(src, a="A",b="B",c="C")
