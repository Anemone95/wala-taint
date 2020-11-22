package top.anemone.wala.taintanalysis.transferfunction;

import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.dataflow.graph.BitVectorIdentity;
import com.ibm.wala.fixpoint.BitVectorVariable;
import com.ibm.wala.fixpoint.UnaryOperator;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.Context;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cfg.ExplodedInterproceduralCFG;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAReturnInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.intset.BitVectorIntSet;
import com.ibm.wala.util.intset.OrdinalSetMapping;
import top.anemone.wala.taintanalysis.Utils;
import top.anemone.wala.taintanalysis.domain.IndexedTaintVar;
import top.anemone.wala.taintanalysis.domain.TaintVar;
import top.anemone.wala.taintanalysis.domain.Statement;

import java.util.*;

public class EdgeTransfer extends UnaryOperator<BitVectorVariable> {


    private final BasicBlockInContext<IExplodedBasicBlock> src;
    private final BasicBlockInContext<IExplodedBasicBlock> dst;
    private final OrdinalSetMapping<TaintVar> taintVars;
    private final CallGraph callGraph;
    private final TaintVar fakeSource;
    private final TaintVar fakeSink;
    private final ExplodedInterproceduralCFG icfg;

    public EdgeTransfer(BasicBlockInContext<IExplodedBasicBlock> src, BasicBlockInContext<IExplodedBasicBlock> dst, OrdinalSetMapping<TaintVar> vars,
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
                // 实参
                IndexedTaintVar paraSrc = getOrCreateTaintVar(paraSrcVar, srcInst, src.getNode().getContext(), src.getMethod());
                // 形参
                IndexedTaintVar paraDst = getOrCreateTaintVar(paraDstVar, dstInst, dst.getNode().getContext(), dst.getMethod());
                // 传递域
                paraDst.var.fields = paraSrc.var.fields;
                Utils.GetTaintRet taintParam = Utils.getTaint(paraSrc.var, this.taintVars, rhs);
                if (taintParam != null) {
                    TaintVar callSite = new TaintVar(paraSrcVar, src.getNode().getContext(), src.getMethod(), srcInst, TaintVar.Type.CALL_SITE);
                    TaintVar callee = new TaintVar(paraDstVar, dst.getNode().getContext(), dst.getMethod(), dstInst, TaintVar.Type.METHOD_ENTRY);
                    if (taintParam.fromField == null) {
                        callSite.addPrevStatement(new Statement(taintParam.taintVar));
                        gen.add(paraDst.index);
                    } else {
                        callSite.addPrevStatement(taintParam.fromField);
                    }
                    callee.addPrevStatement(new Statement(callSite));
                    paraDst.var.clearPrevStatements();
                    try {
                        dst.getNode().getMethod().getParameterSourcePosition(i);
                    } catch (InvalidClassFileException e) {
                        e.printStackTrace();
                    }
                    paraDst.var.addPrevStatement(new Statement(callee));
                }
            }

        } else if (src.isExitBlock() && !dst.isExitBlock()) {
            // exit to return
            Iterator<BasicBlockInContext<IExplodedBasicBlock>> predNodes = icfg.getPredNodes(dst);

            List<Statement> possibleTaintRets = new LinkedList<>();
            if (predNodes.hasNext()) {
                Arrays.stream(src.getNode().getIR().getInstructions()).filter(e -> e instanceof SSAReturnInstruction)
                        .forEach(inst -> {
                                    for (int i = 0; i < inst.getNumberOfUses(); i++) {
                                        IndexedTaintVar indexedRetVar = getOrCreateTaintVar(inst.getUse(i), inst,
                                                src.getNode().getContext(), src.getMethod());
                                        Utils.GetTaintRet foundTaint = Utils.getTaint(indexedRetVar.var, taintVars, rhs);
                                        Statement retStmt = new Statement(new TaintVar(inst.getUse(i),
                                                src.getNode().getContext(), src.getMethod(), inst, TaintVar.Type.RET));
                                        if (foundTaint != null) {
                                            retStmt.taintVar.addPrevStatement(new Statement(indexedRetVar.var));
                                            possibleTaintRets.add(retStmt);
                                        }
                                    }
                                }
                        );
            }
            while (predNodes.hasNext()) {
                BasicBlockInContext<IExplodedBasicBlock> predNode = predNodes.next();
                if (!icfg.hasEdge(predNode, icfg.getEntry(src.getNode()))) {
                    continue;
                }

                SSAInstruction invokeInst = predNode.getDelegate().getInstruction();
                IndexedTaintVar outerVar;
                try {
                    outerVar = getOrCreateTaintVar(invokeInst.getDef(),
                            invokeInst, predNode.getNode().getContext(), predNode.getMethod());
                } catch (AssertionError e){
                    continue;
                }
                for (Statement retTaintStmt : possibleTaintRets) {
                    outerVar.var.addPrevStatement(retTaintStmt);
                    gen.add(outerVar.index);
                }
                kill.add(outerVar.index);
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
