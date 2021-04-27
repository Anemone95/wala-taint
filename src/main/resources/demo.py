import subprocess
from flask import Flask, render_template, request
import os

req_param = request.form['suggestion']
os.system(req_param)
