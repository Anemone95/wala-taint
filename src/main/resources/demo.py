from flask import request
import subprocess

src=request.form
p = subprocess.Popen(src, a="A",b="B",c="C")
