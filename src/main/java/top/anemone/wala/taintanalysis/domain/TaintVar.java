package top.anemone.wala.taintanalysis.domain;

import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.Context;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.types.FieldReference;

import java.util.*;


public class TaintVar {

    public enum Type {
        DEF, PUT, TEMP, CALL_SITE, METHOD_ENTRY
    }

    public final Context context;
    public final List<TaintVar> propagateTaintVars;
    public final IMethod method;
    public final SSAInstruction inst;
    public int varNo;
    public Map<FieldReference, TaintVar> fields;
    public Type type;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TaintVar taintVar = (TaintVar) o;
        return varNo == taintVar.varNo &&
                Objects.equals(context, taintVar.context);
    }

    public TaintVar getField(FieldReference f) {
        return fields.get(f);
    }

    public TaintVar putField(FieldReference f, TaintVar t) {
        return fields.put(f, t);
    }

    @Override
    public int hashCode() {
        return Objects.hash(context, varNo);
    }

    public TaintVar(int varNo, Context context, IMethod method, SSAInstruction defInst) {
        this.varNo = varNo;
        this.context = context;
        this.propagateTaintVars = new LinkedList<>();
        this.method = method;
        this.inst = defInst;
        this.fields = new HashMap<>();
        this.type = Type.DEF;
    }

    public TaintVar(int varNo, Context context, IMethod method, SSAInstruction defInst, Type type) {
        this.varNo = varNo;
        this.context = context;
        this.propagateTaintVars = new LinkedList<>();
        this.method = method;
        this.inst = defInst;
        this.fields = new HashMap<>();
        this.type = type;
    }

    @Deprecated
    public void addNextTaintVar(TaintVar t) {
        propagateTaintVars.add(t);
    }

    public IMethod.SourcePosition getPosition() {
        if (method != null && inst != null) {
            try {
                return method.getSourcePosition(inst.iIndex());
            } catch (InvalidClassFileException e) {
                e.printStackTrace();
            }
        }
        return new IMethod.SourcePosition() {
            @Override
            public int getFirstLine() {
                return 0;
            }

            @Override
            public int getLastLine() {
                return 0;
            }

            @Override
            public int getFirstCol() {
                return 0;
            }

            @Override
            public int getLastCol() {
                return 0;
            }

            @Override
            public int getFirstOffset() {
                return 0;
            }

            @Override
            public int getLastOffset() {
                return 0;
            }

            @Override
            public int compareTo(IMethod.SourcePosition o) {
                return 0;
            }
        };
    }

}
