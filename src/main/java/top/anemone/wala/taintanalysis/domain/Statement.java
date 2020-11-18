package top.anemone.wala.taintanalysis.domain;

import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ssa.SSAInstruction;

import java.util.Objects;

public class Statement {
    public final IMethod method;
    public final TaintVar.Type type;
    public TaintVar taintVar;
    public SSAInstruction ssaInstruction;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Statement that = (Statement) o;
        return Objects.equals(method, that.method) &&
                type == that.type &&
                Objects.equals(taintVar, that.taintVar) &&
                Objects.equals(ssaInstruction, that.ssaInstruction);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, type, taintVar, ssaInstruction);
    }

    public Statement(TaintVar taintVar){
        this.taintVar=taintVar;
        this.ssaInstruction=taintVar.inst;
        this.method=taintVar.method;
        this.type=taintVar.type;
    }
}
