package top.anemone.wala.taintanalysis.domain;

public class IndexedTaintVar {
    public int index;
    public TaintVar var;

    public IndexedTaintVar(int index, TaintVar taintVar) {
        this.index = index;
        this.var = taintVar;
    }
}
