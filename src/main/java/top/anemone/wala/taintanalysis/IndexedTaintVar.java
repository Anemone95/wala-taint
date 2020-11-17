package top.anemone.wala.taintanalysis;

class IndexedTaintVar {
    public int index;
    public TaintVar var;

    IndexedTaintVar(int index, TaintVar taintVar) {
        this.index = index;
        this.var = taintVar;
    }
}
