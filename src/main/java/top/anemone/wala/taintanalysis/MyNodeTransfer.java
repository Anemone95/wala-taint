package top.anemone.wala.taintanalysis;

import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.fixpoint.BitVectorVariable;
import com.ibm.wala.fixpoint.UnaryOperator;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.Context;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.SSAAbstractInvokeInstruction;
import com.ibm.wala.ssa.SSAGetInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAPutInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.util.intset.BitVectorIntSet;
import com.ibm.wala.util.intset.OrdinalSetMapping;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class MyNodeTransfer extends UnaryOperator<BitVectorVariable> {

    private final BasicBlockInContext<IExplodedBasicBlock> node;
    private final OrdinalSetMapping<TaintVar> taintVars;
    private final CallGraph callGraph;
    private final TaintVar fakeSource;
    private final TaintVar fakeSink;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MyNodeTransfer that = (MyNodeTransfer) o;
        return node.equals(that.node) &&
                callGraph.equals(that.callGraph) &&
                fakeSource.equals(that.fakeSource) &&
                fakeSink.equals(that.fakeSink);
    }

    @Override
    public int hashCode() {
        return Objects.hash(node, callGraph, fakeSource, fakeSink);
    }

    public MyNodeTransfer(BasicBlockInContext<IExplodedBasicBlock> node, OrdinalSetMapping<TaintVar> vars,
                          CallGraph callGraph, TaintVar source, TaintVar sink) {
        this.node = node;
        this.taintVars = vars;
        this.callGraph = callGraph;
        this.fakeSource = source;
        this.fakeSink = sink;
    }

    @Override
    public byte evaluate(BitVectorVariable lhs, BitVectorVariable rhs) {
        if (rhs == null) {
            throw new IllegalArgumentException("rhs == null");
        }
        if (lhs == null) {
            throw new IllegalArgumentException("lhs == null");
        }
        IExplodedBasicBlock ebb = node.getDelegate();
        SSAInstruction instruction = ebb.getInstruction();
        CGNode cgNode = node.getNode();
        Context context = cgNode.getContext();
        IMethod method = cgNode.getMethod();

        BitVectorIntSet gen = new BitVectorIntSet();
        BitVectorIntSet kill = new BitVectorIntSet();

        if (instruction != null) {
            boolean isHandled = false;
            if (instruction instanceof SSAGetInstruction) {
                // source
                if (instruction.toString().contains("form")) {
                    IndexedTaintVar taintVar = getOrCreateTaintVar(instruction.getDef(), instruction, context, method);
                    fakeSource.addNextTaintVar(this.taintVars.getMappedObject(taintVar.index));
                    gen.add(taintVar.index);
                    isHandled = true;
                }
            }
            if (instruction instanceof SSAAbstractInvokeInstruction) {
                // sink
                String sinkFunc = "os/function/system";
                int sinkParam = 1;
                if (instruction.getNumberOfUses() - 1 >= sinkParam) {
                    CallSiteReference cs = ((SSAAbstractInvokeInstruction) instruction).getCallSite();
                    for (CGNode callee : this.callGraph.getPossibleTargets(cgNode, cs)) {
                        // sink pattern(os/function/system)
                        IndexedTaintVar taintVar = getOrCreateTaintVar(instruction.getUse(sinkParam), instruction, context, method);
                        if (callee.getMethod().getReference().toString().contains(sinkFunc) && taintVar.index != -1 && rhs.get(taintVar.index)) {
                            TaintVar def = taintVar.var;
                            TaintVar use = new TaintVar(-instruction.getUse(sinkParam), context, method, instruction);
                            def.addNextTaintVar(use);
                            use.addNextTaintVar(fakeSink);
                            System.out.println("Vulnerable:");
                            new PrintUtil().printPath(fakeSource, fakeSink);

                        }
                    }
                }
            }

            if (instruction instanceof SSAPutInstruction) {
                SSAPutInstruction inst = (SSAPutInstruction) instruction;
                FieldReference fieldReference = inst.getDeclaredField();
                IndexedTaintVar obj = getOrCreateTaintVar(inst.getUse(0), instruction, context, method);
                IndexedTaintVar fieldObj = getOrCreateTaintVar(inst.getUse(1), instruction, context, method);
                // put fieldObj into obj
                obj.var.fields.put(fieldReference, fieldObj.var);
                // 如果存在污染传递，则将其加入propagateTaintVars
                if (Utils.getTaint(obj.var, this.taintVars, rhs)!=null) {
                    obj.var.addNextTaintVar(fieldObj.var);
                    TaintVar printTaintVar = new TaintVar(inst.getUse(0), context, method, inst, TaintVar.Type.PUT);
                    fieldObj.var.addNextTaintVar(printTaintVar);
                }
                isHandled = true;
            }

            if (instruction instanceof SSAGetInstruction) {
                SSAGetInstruction inst = (SSAGetInstruction) instruction;
                FieldReference field = inst.getDeclaredField();
                IndexedTaintVar obj = getOrCreateTaintVar(inst.getUse(0), instruction, context, method);
                IndexedTaintVar nextTaintVar = getOrCreateTaintVar(instruction.getDef(), instruction, context, method);
                nextTaintVar.var.fields=obj.var.fields; // 获取右侧对象所有域
                if (isTaint(obj.var, rhs)) {
                    // 如果目标本身污染，那么其中所有域被污染
                    obj.var.addNextTaintVar(nextTaintVar.var);
                    gen.add(nextTaintVar.index);
                } else {
                    // 如果目标为污染，那么检查其域是否被污染
                    TaintVar fieldObj = obj.var.getField(field);
                    if (isTaint(fieldObj, rhs)) {
                        // FIXME: 应该逆向找field赋值依赖语句，而不是直接加所有的语句(a.b.c=d.e)
                        List<TaintVar> prevTaintVars=fieldObj.propagateTaintVars.stream().filter(e -> e.type == TaintVar.Type.PUT)
                                .collect(Collectors.toList());
                        for (TaintVar prevTaintVar: prevTaintVars) {
                            prevTaintVar.addNextTaintVar(nextTaintVar.var);
                        }
                        gen.add(nextTaintVar.index);
                    }
                }
                isHandled = true;
            }

            if (!isHandled) {
                for (int i = 0; i < instruction.getNumberOfUses(); i++) {
                    // propagate
                    TaintVar tVar = new TaintVar(instruction.getUse(i), context, method, instruction);
                    int idx = this.taintVars.getMappedIndex(tVar);
                    if (idx != -1 && rhs.get(idx)) {
                        // 存在污点
                        TaintVar prevTaintVar = this.taintVars.getMappedObject(idx);
                        IndexedTaintVar nextTaintVar = getOrCreateTaintVar(instruction.getDef(), instruction, context, method);
                        prevTaintVar.addNextTaintVar(nextTaintVar.var);
                        gen.add(nextTaintVar.index);
                    }
                }
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
    public String toString() {
        return "MyNodeTransfer{" + "node=" + node + '}';
    }

    private IndexedTaintVar getOrCreateTaintVar(int var, SSAInstruction instruction, Context context, IMethod method) {
        TaintVar taintVar = new TaintVar(var, context, method, instruction, TaintVar.Type.TEMP);
        int idx = this.taintVars.getMappedIndex(taintVar);
        if (idx < 0) {
            taintVar.type= TaintVar.Type.DEF;
            idx = this.taintVars.add(taintVar);
        } else {
            taintVar = this.taintVars.getMappedObject(idx);
        }
        return new IndexedTaintVar(idx, taintVar);
    }


    private boolean isTaint(TaintVar taintVar, BitVectorVariable rhs) {
        int idx = this.taintVars.getMappedIndex(taintVar);
        return idx != -1 && rhs.get(idx);
    }
}
