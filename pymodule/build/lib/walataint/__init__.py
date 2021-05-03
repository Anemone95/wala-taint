source_field="SOURCE_FIELD"
def source_function():
    return "SOURCE_FUNCTION"
sink_field=None
def sink_function(taint):
    print('SINK FUNCTION INVOKED, ARGS: '+taint)
def sanitizer(taint):
    return "SANITIZER"
