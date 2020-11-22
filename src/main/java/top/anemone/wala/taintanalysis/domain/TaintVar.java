package top.anemone.wala.taintanalysis.domain;

import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.Context;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.types.FieldReference;

import java.util.*;


public class TaintVar {

    public enum Type {
        DEF, PUT, GET_OBJ, TEMP, CALL_SITE, METHOD_ENTRY, RET
    }

    public final Context context;
    private final Set<Statement> prevStatements;

    public Set<Statement> getPrevStatements() {
        return prevStatements;
    }

    public void addPrevStatement(Statement prevStatement) {
        this.prevStatements.add(prevStatement);
    }

    public void clearPrevStatements(){
        this.prevStatements.clear();
    }
    public void reloadPrevStatements(Set<Statement> prevStatements) {
        this.prevStatements.clear();
        this.prevStatements.addAll(prevStatements);
    }

    public final IMethod method;
    public final SSAInstruction inst;
    public int varNo;
    public Map<FieldReference, Statement> fields;
    public Type type;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TaintVar taintVar = (TaintVar) o;
        return varNo == taintVar.varNo &&
                Objects.equals(context, taintVar.context) && Objects.equals(method, taintVar.method) ;
    }

    public Statement getField(FieldReference f) {
        return fields.get(f);
    }

    public Statement putField(FieldReference f, Statement t) {
        return fields.put(f, t);
    }

    @Override
    public int hashCode() {
        return Objects.hash(context, varNo, method);
    }

    public TaintVar(int varNo, Context context, IMethod method, SSAInstruction defInst) {
        this.varNo = varNo;
        this.context = context;
        this.method = method;
        this.inst = defInst;
        this.fields = new HashMap<>();
        this.type = Type.DEF;
        this.prevStatements = new HashSet<>();
    }

    public TaintVar(int varNo, Context context, IMethod method, SSAInstruction defInst, Type type) {
        this.varNo = varNo;
        this.context = context;
        this.method = method;
        this.inst = defInst;
        this.fields = new HashMap<>();
        this.type = type;
        this.prevStatements = new HashSet<>();
    }


    @Override
    public String toString() {
        return "TaintVar{" +
                "context=" + context +
                ", varNo=" + varNo +
                ", type=" + type +
                ", position" + getPosition() +
                '}';
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
