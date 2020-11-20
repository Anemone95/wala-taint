package top.anemone.wala.taintanalysis.transferfunction;

import com.ibm.wala.dataflow.graph.AbstractMeetOperator;
import com.ibm.wala.dataflow.graph.BitVectorUnion;
import com.ibm.wala.fixpoint.BitVectorVariable;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.util.intset.OrdinalSetMapping;
import top.anemone.wala.taintanalysis.domain.TaintVar;

public class UnionOperator extends AbstractMeetOperator<BitVectorVariable> {


    private final OrdinalSetMapping<TaintVar> taintVars;
    private final CallGraph callGraph;

    public UnionOperator(OrdinalSetMapping<TaintVar> vars,
                         CallGraph callGraph ) {
        this.taintVars = vars;
        this.callGraph = callGraph;
    }
    
    @Override
    public byte evaluate(BitVectorVariable lhs, BitVectorVariable[] rhs) {

        if (lhs == null) {
            throw new IllegalArgumentException("null lhs");
        }
        if (rhs == null) {
            throw new IllegalArgumentException("rhs == null");
        }
        BitVectorVariable U = new BitVectorVariable();
        U.copyState(lhs);
        for (BitVectorVariable R : rhs) {
            U.addAll(R);
        }
        if (!lhs.sameValue(U)) {
            lhs.copyState(U);
            return CHANGED;
        } else {
            return NOT_CHANGED;
        }
    }

    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    public boolean equals(Object o) {
        return false;
    }

    @Override
    public String toString() {
        return null;
    }
}
