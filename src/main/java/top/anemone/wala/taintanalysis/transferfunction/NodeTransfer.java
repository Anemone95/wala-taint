package top.anemone.wala.taintanalysis.transferfunction;

import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.fixpoint.BitVectorVariable;
import com.ibm.wala.fixpoint.UnaryOperator;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.Context;
import com.ibm.wala.ipa.callgraph.propagation.AllocationSiteInNode;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.callgraph.propagation.LocalPointerKey;
import com.ibm.wala.ipa.callgraph.propagation.PointerAnalysis;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cfg.ExplodedInterproceduralCFG;
import com.ibm.wala.ssa.*;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.util.intset.BitVectorIntSet;
import com.ibm.wala.util.intset.OrdinalSet;
import com.ibm.wala.util.intset.OrdinalSetMapping;
import top.anemone.wala.taintanalysis.result.PrintTraverser;
import top.anemone.wala.taintanalysis.Utils;
import top.anemone.wala.taintanalysis.domain.IndexedTaintVar;
import top.anemone.wala.taintanalysis.domain.Statement;
import top.anemone.wala.taintanalysis.domain.TaintVar;
import top.anemone.wala.taintanalysis.result.TaintGraphTraverser;

import java.util.Iterator;
import java.util.Objects;
import java.util.Set;

public class NodeTransfer extends UnaryOperator<BitVectorVariable> {

    private final BasicBlockInContext<IExplodedBasicBlock> node;
    private final OrdinalSetMapping<TaintVar> taintVars;
    private final CallGraph callGraph;
    private final TaintVar fakeSource;
    private final TaintVar fakeSink;
    private final TaintGraphTraverser resultProcessor;
    private final PointerAnalysis<? super InstanceKey> pointerAnalysis;

    public NodeTransfer(BasicBlockInContext<IExplodedBasicBlock> node,
                        OrdinalSetMapping<TaintVar> taintVars, CallGraph callGraph,
                        PointerAnalysis<? super InstanceKey> pointerAnalysis,
                        TaintVar source, TaintVar sink, TaintGraphTraverser resultProcessor) {
        this.node = node;
        this.taintVars = taintVars;
        this.callGraph = callGraph;
        this.fakeSource = source;
        this.fakeSink = sink;
        this.resultProcessor = resultProcessor;
        this.pointerAnalysis=pointerAnalysis;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NodeTransfer that = (NodeTransfer) o;
        return node.equals(that.node) &&
                callGraph.equals(that.callGraph) &&
                fakeSource.equals(that.fakeSource) &&
                fakeSink.equals(that.fakeSink);
    }

    @Override
    public int hashCode() {
        return Objects.hash(node, callGraph, fakeSource, fakeSink);
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

//                MethodReference flask =
//                        MethodReference.findOrCreate(
//                                TypeReference.findOrCreate(PythonTypes.pythonLoader, "Lflask"),
//                                new Selector(
//                                        Atom.findOrCreateUnicodeAtom("import"),
//                                        Descriptor.findOrCreateUTF8("()Lflask;")));

                LocalPointerKey objKey = new LocalPointerKey(cgNode, instruction.getDef()); // FIXME: getUse=-1
                OrdinalSet<? super InstanceKey> objs = pointerAnalysis.getPointsToSet(objKey);
                for (Object x : objs) {
                    System.out.println(x);
                    if (x instanceof AllocationSiteInNode) {
                        AllocationSiteInNode xx = (AllocationSiteInNode) x;
                        System.out.println(x);
                        System.out.println(((AllocationSiteInNode) x).getSite());
//                        if (xx.getNode().getMethod().getReference().equals(flask) &&
//                                xx.getSite().getProgramCounter() == 5) {
//                            return true;
//                        }
                    }
                }


                if (instruction.toString().contains("suggestion")) {
                    IndexedTaintVar taintVar = getOrCreateTaintVar(instruction.getDef(), instruction, context, method);
//                    fakeSource.addNextTaintVar(this.taintVars.getMappedObject(taintVar.index));
                    taintVar.var.addPrevStatement(new Statement(fakeSource));
                    gen.add(taintVar.index);
                    isHandled = true;
                }
            }
            if (instruction instanceof SSAAbstractInvokeInstruction) {
                // sink
                String sinkFunc = "walataint/function/sink";
                int sinkParam = 1;
                if (instruction.getNumberOfUses() - 1 >= sinkParam) {
                    CallSiteReference cs = ((SSAAbstractInvokeInstruction) instruction).getCallSite();
                    Set<CGNode> callees = this.callGraph.getPossibleTargets(cgNode, cs);
                    // 非黑盒函数污点在函数内处理，黑盒函数默认传播污点,
                    if (callees.size() != 0) {
                        isHandled = true;
                    } else {
                        // 清除上一轮污点
                        TaintVar lhVar = new TaintVar(instruction.getDef(), context, method, instruction, TaintVar.Type.DEF);
                        kill.add(this.taintVars.add(lhVar));
                    }
                    for (CGNode callee : callees) {
                        // sink pattern(os/function/system)
                        IndexedTaintVar taintVar = getOrCreateTaintVar(instruction.getUse(sinkParam), instruction, context, method);
                        if (callee.getMethod().getReference().toString().contains(sinkFunc) && taintVar.index != -1 && rhs.get(taintVar.index)) {
                            TaintVar def = taintVar.var;
                            TaintVar use = new TaintVar(-instruction.getUse(sinkParam), context, method, instruction);
                            use.addPrevStatement(new Statement(def));
                            fakeSink.addPrevStatement(new Statement(use));
                            System.out.println("Vulnerable:");
                            resultProcessor.traverse(new Statement(fakeSource), new Statement(fakeSink));
                        }
                    }
                }
            }

            if (instruction instanceof SSAPutInstruction && instruction.getNumberOfUses() >= 2) {
                // 域敏感时无法兼顾流敏感（要做代价等同于流敏感指针分析），因此当field本身是污点时，不清除
                SSAPutInstruction inst = (SSAPutInstruction) instruction;
                FieldReference fieldReference = inst.getDeclaredField();
                IndexedTaintVar obj = getOrCreateTaintVar(inst.getUse(0), instruction, context, method);
                IndexedTaintVar fieldObj = getOrCreateTaintVar(inst.getUse(1), instruction, context, method);
                Statement oldFieldVar = obj.var.getField(inst.getDeclaredField());
                // put fieldObj into obj
                // 如果存在污染传递，标记，但是不能直接依赖fieidobj定义的taintvar，得重新定义新的put
                Utils.GetTaintRet rhsTaint = Utils.getTaint(fieldObj.var, this.taintVars, rhs);
                if (rhsTaint != null) {
                    TaintVar putVar = new TaintVar(inst.getUse(1), context, method, inst, TaintVar.Type.PUT);
                    putVar.fields = fieldObj.var.fields;
                    if (rhsTaint.fromField == null) {
                        // 污点来自对象本身
                        putVar.addPrevStatement(new Statement(rhsTaint.taintVar));
                    } else {
                        // 污点来自对象里的域
                        putVar.addPrevStatement(rhsTaint.fromField);
                    }
                    obj.var.putField(fieldReference, new Statement(putVar));
                } else if (oldFieldVar != null && Utils.getTaint(oldFieldVar.taintVar, this.taintVars, rhs) != null) {
                    // 老field有污点，不重新赋值（流不敏感）
                    System.err.println(obj.var + "'s field: " + inst.getDeclaredField().getName() +
                            " had taint in some where. Field is not flow sensitive so not clean, may cause FP");
                } else {
                    // 无污点，赋值
                    obj.var.putField(fieldReference, new Statement(fieldObj.var));
                }
                isHandled = true;
            }

            if (instruction instanceof SSAGetInstruction) {
                SSAGetInstruction inst = (SSAGetInstruction) instruction;
                FieldReference field = inst.getDeclaredField();
                IndexedTaintVar obj = getOrCreateTaintVar(inst.getUse(0), instruction, context, method);

                IndexedTaintVar leftVar = getOrCreateTaintVar(instruction.getDef(), instruction, context, method);
                kill.add(leftVar.index);
                Utils.GetTaintRet rightTaintVar = Utils.getTaint(obj.var, this.taintVars, rhs);
                Statement fieldObj = obj.var.getField(field);
                if (rightTaintVar == null) {
                    if (fieldObj != null) {
                        leftVar.var.fields = fieldObj.taintVar.fields; // 获取右侧对象所有域
                    }
                } else if (rightTaintVar.fromField == null) {
                    // 如果目标本身污染，那么其中所有域被污染
//                    leftVar.var.clearPrevStatements();
                    leftVar.var.addPrevStatement(new Statement(obj.var));
                    gen.add(leftVar.index);
                } else {
                    // 如果目标未污染，那么其域被污染
                    boolean objInParam = false;
                    for (int i = 0; i < method.getNumberOfParameters(); i++) {
                        if (cgNode.getIR().getSymbolTable().getParameter(i) == obj.var.varNo) {
                            objInParam = true;
                            break;
                        }
                    }
                    leftVar.var.clearPrevStatements();
                    if (objInParam) {
                        // 目标是函数参数传下来的
                        leftVar.var.addPrevStatement(new Statement(obj.var));
                    } else {
                        leftVar.var.addPrevStatement(rightTaintVar.fromField);
                    }
                    gen.add(leftVar.index);
                }

                isHandled = true;
            }


            if (!isHandled) {
                for (int i = 0; i < instruction.getNumberOfUses(); i++) {
                    // propagate
                    TaintVar rhsTaint = new TaintVar(instruction.getUse(i), context, method, instruction);
                    Utils.GetTaintRet prevTaintVar = Utils.getTaint(rhsTaint, this.taintVars, rhs);
                    if (prevTaintVar != null) {
                        // 存在污点
                        IndexedTaintVar nextTaintVar = getOrCreateTaintVar(instruction.getDef(), instruction, context, method);
                        if (prevTaintVar.fromField == null) {
                            nextTaintVar.var.addPrevStatement(new Statement(prevTaintVar.taintVar));
                        } else {
                            nextTaintVar.var.addPrevStatement(prevTaintVar.fromField);
                        }
                        gen.add(nextTaintVar.index);
                    }
                }
            }

        }

        Iterator<SSAPhiInstruction> phiInsts = node.iteratePhis();
        while (phiInsts.hasNext()) {
            SSAPhiInstruction phiInst = phiInsts.next();
            IndexedTaintVar lhVar = getOrCreateTaintVar(phiInst.getDef(), instruction, context, method);
            // union taint
            for (int i = 0; i < phiInst.getNumberOfUses(); i++) {
                IndexedTaintVar rhVarI = getOrCreateTaintVar(phiInst.getUse(i), instruction, context, method);
                Utils.GetTaintRet taintVar = Utils.getTaint(rhVarI.var, this.taintVars, rhs);
                if (taintVar != null) {
                    if (taintVar.fromField == null) {
                        lhVar.var.addPrevStatement(new Statement(taintVar.taintVar));
                        gen.add(lhVar.index);
                    } else {
                        lhVar.var.fields = rhVarI.var.fields;
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
            taintVar.type = TaintVar.Type.DEF;
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
