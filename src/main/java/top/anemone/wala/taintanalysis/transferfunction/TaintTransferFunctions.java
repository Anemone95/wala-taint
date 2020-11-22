package top.anemone.wala.taintanalysis.transferfunction;

import com.ibm.wala.dataflow.graph.*;
import com.ibm.wala.fixpoint.BitVectorVariable;
import com.ibm.wala.fixpoint.UnaryOperator;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.callgraph.propagation.PointerAnalysis;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cfg.ExplodedInterproceduralCFG;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.intset.OrdinalSetMapping;
import top.anemone.wala.taintanalysis.domain.TaintVar;
import top.anemone.wala.taintanalysis.result.TaintGraphTraverser;

public class TaintTransferFunctions implements ITransferFunctionProvider<BasicBlockInContext<IExplodedBasicBlock>, BitVectorVariable> {

    private final OrdinalSetMapping<TaintVar> taintVars;
    private final CallGraph callGraph;
    private final TaintVar source;
    private final TaintVar sink;
    private final ExplodedInterproceduralCFG icfg;
    private final TaintGraphTraverser resultProcessor;
    private final PointerAnalysis<? super InstanceKey> pointerAnalysis;


    public TaintTransferFunctions(OrdinalSetMapping<TaintVar> vars, CallGraph callGraph,
                                  ExplodedInterproceduralCFG icfg, TaintVar source, TaintVar sink,
                                  PointerAnalysis<? super InstanceKey> pointerAnalysis, TaintGraphTraverser resultProcessor) {
        this.taintVars = vars;
        this.callGraph = callGraph;
        this.icfg=icfg;
        this.source = source;
        this.sink = sink;
        this.resultProcessor=resultProcessor;
        this.pointerAnalysis=pointerAnalysis;
    }

    @Override
    public UnaryOperator<BitVectorVariable> getNodeTransferFunction(BasicBlockInContext<IExplodedBasicBlock> node) {

        return new NodeTransfer(node, this.taintVars, this.callGraph, this.pointerAnalysis,this.source, this.sink, this.resultProcessor);
    }

    @Override
    public UnaryOperator<BitVectorVariable> getEdgeTransferFunction(BasicBlockInContext<IExplodedBasicBlock> src, BasicBlockInContext<IExplodedBasicBlock> dst) {
        return new EdgeTransfer(src, dst, this.taintVars, this.callGraph, this.icfg, this.source, this.sink);
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
