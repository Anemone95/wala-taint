import subprocess
from flask import Flask, render_template, request
import os

req_param = request.form['suggestion']
b=req_param+"A"
# b=b[:-10]
os.system(b)

