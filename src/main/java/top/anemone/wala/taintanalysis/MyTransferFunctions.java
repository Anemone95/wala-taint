package top.anemone.wala.taintanalysis;

import com.ibm.wala.cast.python.ssa.PythonInvokeInstruction;
import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.dataflow.graph.*;
import com.ibm.wala.fixpoint.BitVectorVariable;
import com.ibm.wala.fixpoint.UnaryOperator;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.Context;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cfg.ExplodedInterproceduralCFG;
import com.ibm.wala.ipa.slicer.ParamCaller;
import com.ibm.wala.ssa.SSAAbstractInvokeInstruction;
import com.ibm.wala.ssa.SSAGetInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAPutInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.intset.BitVector;
import com.ibm.wala.util.intset.OrdinalSetMapping;

import java.util.HashSet;

public class MyTransferFunctions implements ITransferFunctionProvider<BasicBlockInContext<IExplodedBasicBlock>, BitVectorVariable> {

    private final OrdinalSetMapping<TaintVar> taintVars;
    private final CallGraph callGraph;
    private final TaintVar source;
    private final TaintVar sink;
    private final ExplodedInterproceduralCFG icfg;


    public MyTransferFunctions(OrdinalSetMapping<TaintVar> vars, CallGraph callGraph, ExplodedInterproceduralCFG icfg, TaintVar source, TaintVar sink) {
        this.taintVars = vars;
        this.callGraph = callGraph;
        this.icfg=icfg;
        this.source = source;
        this.sink = sink;
    }

    @Override
    public UnaryOperator<BitVectorVariable> getNodeTransferFunction(BasicBlockInContext<IExplodedBasicBlock> node) {

        return new MyNodeTransfer(node, this.taintVars, this.callGraph, this.source, this.sink);
    }

    @Override
    public UnaryOperator<BitVectorVariable> getEdgeTransferFunction(BasicBlockInContext<IExplodedBasicBlock> src, BasicBlockInContext<IExplodedBasicBlock> dst) {
        return new MyEdgeTransfer(src, dst, this.taintVars, this.callGraph, this.icfg, this.source, this.sink);
    }

    @Override
    public boolean hasEdgeTransferFunctions() {
        return true;
    }

    @Override
    public boolean hasNodeTransferFunctions() {
        return true;
    }

    @Override
    public AbstractMeetOperator<BitVectorVariable> getMeetOperator() {
        return BitVectorUnion.instance();
    }
}
