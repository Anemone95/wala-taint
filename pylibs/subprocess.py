import walataint

def Popen(taint,*args,**kwargs):
    walataint.sink_func(taint)
