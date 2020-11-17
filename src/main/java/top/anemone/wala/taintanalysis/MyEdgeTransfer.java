package top.anemone.wala.taintanalysis;

import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.dataflow.graph.BitVectorIdentity;
import com.ibm.wala.fixpoint.BitVectorVariable;
import com.ibm.wala.fixpoint.UnaryOperator;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.Context;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cfg.ExplodedInterproceduralCFG;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.intset.BitVectorIntSet;
import com.ibm.wala.util.intset.OrdinalSetMapping;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class MyEdgeTransfer extends UnaryOperator<BitVectorVariable> {


    private final BasicBlockInContext<IExplodedBasicBlock> src;
    private final BasicBlockInContext<IExplodedBasicBlock> dst;
    private final OrdinalSetMapping<TaintVar> taintVars;
    private final CallGraph callGraph;
    private final TaintVar fakeSource;
    private final TaintVar fakeSink;
    private final ExplodedInterproceduralCFG icfg;

    public MyEdgeTransfer(BasicBlockInContext<IExplodedBasicBlock> src, BasicBlockInContext<IExplodedBasicBlock> dst, OrdinalSetMapping<TaintVar> vars,
                          CallGraph callGraph, ExplodedInterproceduralCFG icfg, TaintVar source, TaintVar sink) {
        this.src = src;
        this.dst = dst;
        this.taintVars = vars;
        this.callGraph = callGraph;
        this.icfg = icfg;
        this.fakeSource = source;
        this.fakeSink = sink;
    }

    /**
     * for direct call-to-return edges at a call site, the edge transfer function will kill all facts, since we only want to
     * consider facts that arise from going through the callee
     */
    @Override
    public byte evaluate(BitVectorVariable lhs, BitVectorVariable rhs) {
        BitVectorIntSet gen = new BitVectorIntSet();
        BitVectorIntSet kill = new BitVectorIntSet();

        SSAInstruction srcInst = src.getDelegate().getInstruction();
        SSAInstruction dstInst = dst.getDelegate().getInstruction();

//        System.out.println("-----BB start------");
//        System.out.println("src: "+srcInst+" context: "+src.getNode().getContext());
//        System.out.println("dst: "+dstInst+" context: "+dst.getNode().getContext());
//        System.out.println("-----BB end------");
        if (dst.isEntryBlock()) {
            // call to entry, 传参数
            int numPara = srcInst.getNumberOfUses();
            int numMethodPara = dst.getNode().getIR().getNumberOfParameters();
            if (numPara != numMethodPara && numPara != numMethodPara + 1) {
                System.err.println("parameter number mismatch!");
                return BitVectorIdentity.instance().evaluate(lhs, rhs);
            }
            int offset = 0;
            if (numPara != numMethodPara) {
                offset = 1;
            }
            for (int i = 0; i < numMethodPara; i++) {
                int paraSrcVar = srcInst.getUse(offset + i);
                int paraDstVar = dst.getNode().getIR().getSymbolTable().getParameter(i);
                IndexedTaintVar paraSrc = getOrCreateTaintVar(paraSrcVar, srcInst, src.getNode().getContext(), src.getMethod());
                IndexedTaintVar paraDst = getOrCreateTaintVar(paraDstVar, dstInst, dst.getNode().getContext(), dst.getMethod());
                // 传递域
                paraDst.var.fields = paraSrc.var.fields;
                TaintVar taintParam = Utils.getTaint(paraSrc.var, this.taintVars, rhs);
                if (taintParam != null) {
                    TaintVar callSite = new TaintVar(paraSrcVar, src.getNode().getContext(), src.getMethod(), srcInst, TaintVar.Type.CALL_SITE);
                    TaintVar callee = new TaintVar(paraSrcVar, dst.getNode().getContext(), dst.getMethod(), dstInst, TaintVar.Type.METHOD_ENTRY);
                    if (taintParam.varNo == paraSrc.var.varNo) {
                        // 不涉及域的污点传播
                        paraSrc.var.addNextTaintVar(callSite);
                    } else {
                        TaintVar putStat = findPut(taintParam, paraSrc.var, new HashSet<>()); // 找到put语句
                        if (putStat==null){
                            System.err.println("Put Stat not found");
                            paraSrc.var.addNextTaintVar(callSite);
                        } else {
                            putStat.addNextTaintVar(callSite);
                        }
                    }
                    // FIXME: 找到与[67]相关的, putfield, PUT语句将其插入到后面，(67, putfield, DEF) 实际上是当67.64，67不存在是构造的
                    callSite.addNextTaintVar(callee);
                    callee.addNextTaintVar(paraDst.var);
                    gen.add(paraDst.index);
                }
            }

        } else if (src.isExitBlock() && !dst.isExitBlock()) {
            // exit to return
            Iterator<BasicBlockInContext<IExplodedBasicBlock>> predNodes = icfg.getPredNodes(dst);

            while (predNodes.hasNext()) {
                BasicBlockInContext<IExplodedBasicBlock> predNode = predNodes.next();
//                        if (!icfg.getCallTargets(predNode).contains(src.getNode())) {
//                            continue;
//                        }
                if (!icfg.hasEdge(predNode, icfg.getEntry(src.getNode()))) {
                    continue;
                }
                SSAInstruction invokeInst = predNode.getDelegate().getInstruction();
            }
        }

        // gen kill
        BitVectorVariable U = new BitVectorVariable();
        BitVectorIntSet bv = new BitVectorIntSet();
        if (rhs.getValue() != null) {
            bv.addAll(rhs.getValue());
        }
        bv.removeAll(kill);
        bv.addAll(gen);
        U.addAll(bv.getBitVector());
        if (!lhs.sameValue(U)) {
            lhs.copyState(U);
            return CHANGED;
        } else {
            return NOT_CHANGED;
        }
    }

    private TaintVar findPut(TaintVar taintParam, TaintVar var, Set<TypedTaintVar> book) {
        TaintVar foundPutVar = null;
        for (TaintVar nextTaint : var.propagateTaintVars) {
            if (nextTaint.inst != null && nextTaint.type == TaintVar.Type.PUT && nextTaint.inst.getUse(1) == taintParam.varNo && nextTaint.context.equals(taintParam.context)) {
                return nextTaint;
            }
            TypedTaintVar searchSite = new TypedTaintVar(nextTaint);
            if (!book.contains(searchSite)) {
                book.add(searchSite);
                foundPutVar = findPut(taintParam, nextTaint, book);
                book.remove(searchSite);
                if (foundPutVar != null) {
                    return foundPutVar;
                }
            }
        }
        return foundPutVar;
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

    private IndexedTaintVar getOrCreateTaintVar(int var, SSAInstruction instruction, Context context, IMethod method) {
        TaintVar taintVar = new TaintVar(var, context, method, instruction, TaintVar.Type.DEF);
        int idx = this.taintVars.getMappedIndex(taintVar);
        if (idx < 0) {
            idx = this.taintVars.add(taintVar);
        } else {
            taintVar = this.taintVars.getMappedObject(idx);
        }
        return new IndexedTaintVar(idx, taintVar);
    }


}
