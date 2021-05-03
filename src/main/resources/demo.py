from flask import request
import os

src=request.form["suggest"]
b=src+"A"
os.system(b)
