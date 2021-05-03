# WALA-Taint

A taint analysis demo using WALA. Although currently it still supports Python, this project can be extended to any language which has a WALA frontend.

**Notice: This project is just a demo, so DO NOT use it in any real products**

# Install

This project needs WALA's python-frontend (see [here](https://github.com/Anemone95/wala-python) for more details) Install it at first.

```bash
git clone https://github.com/Anemone95/wala-python
cd wala-python/python-frontend
mvn clean install -DskipTests
```

# Quick Start

Now it still need us write code to config and lunch a analysis (the following code is written in `top.anemone.wala.taintanalysis.TaintAnalysis#main` ):

```java
// add scan target
String filename = "demo.py"; 
Collection<Module> src = new HashSet<>();
// app source code
src.add(new PyScriptModule(TaintAnalysis.class.getClassLoader().getResource(filename)));
// some lib summaries, we will talk it in next subsection
for (File f: Utils.getLibsFromDir("pylibs")){ 
    src.add(new PyLibURLModule(f));
}
// define source and sink
Configuration configuration = new Configuration(true); // true means debug=true
// load default function summaries
configuration.loadPrimitiveConfigs();
new TaintAnalysis().analysis(src, configuration, new PrintTraverser()); // use PrintTraverser to print the taint propagation result.
```

If there is a demo.py like this:

```python
from flask import request
import os


def thread(sys, b, c, d, e):
    sys(b)
    # return b # return b+1,c


def safe(sys, b, c, d, e):
    print(b)


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
```

Then, thanks to the point analysis and dataflow analysis of WALA, we can get the following result:

```
Vulnerable:
os.py [4:4] -> [4:30]
<Code body of function Lscript file:/D:/wala/wala-taint/pylibs/os.py/system>
<Code body of function Lscript file:/D:/wala/wala-taint/pylibs/os.py/system>
demo.py [6:4] -> [6:10]
<Code body of function Lscript file:/D:/wala/wala-taint/target/test-classes/demo.py/thread>
<Code body of function Lscript file:/D:/wala/wala-taint/target/test-classes/demo.py/thread>
demo.py [29:0] -> [29:44]
demo.py [19:0] -> [19:14]
demo.py [19:0] -> [19:14]
demo.py [18:12] -> [18:38]
demo.py [18:12] -> [18:24]
demo.py [1:0] -> [1:0]
demo.py [1:0] -> [1:0]
flask.py [2:0] -> [3:31]
flask.py [2:0] -> [3:31]
```



## Define source, sink and sanitizer

There are two ways to define source, sink or sanitizer.

1. Write function summaries in xml file, and config them. See: `src/main/resources/taint_primitives.xml` and `top.anemone.wala.taintanalysis.Configuration#loadPrimitiveConfigs` for more information.

2. Since the first way is very hard, a more elegant way is to write summaries —— write them in python directly. In these summaries, we can use our `walataint` primitives to define them as a source, sink, or sanitizer.

   To illustrate, firstly, we should install our `walataint` package:

   ```bash
   pip3 install walataint
   ```

   Then, we could write some summaries.

   To write a source function or field, we will use `walataint.source_func()`, like this:

   ```python
   import walataint
   class request:
       form=walataint.source_func() # request.form will be a source
       @classmethod
       def get(cls):
       	return walataint.source_func() # request.get() will return a source
   ```

   To write a sink function or field, we can use `walataint.sink_func()`, like this:

   ```python
   import walataint
   
   def system(taint):
       walataint.sink_func(taint)
   ```

   To write a sanitizer function, we even don't need to use `walataint`, because we just need to write a function which don't propagate taint, like this:

   ```python
   def sanitizer(taint):
       return "nonce" # won't return taint
   ```

   There are already some summaries  in `pylibs`. We suggest you put the new summaries file in the same directory, or you will add more `PyLibURLModule` into `src`.

# Build Python package

```
python3 -m build
python3 -m twine upload dist/*
```



# Limitations

1. Flow-sensitive is not supported when field-sensitive
2. Global variables can't propagate taint
3. Taint propagation result may have some bugs -- it will miss some propagation progresses in some `put` and `get` instructions
4. Time-consuming hasn't been not tested

