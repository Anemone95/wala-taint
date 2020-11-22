package top.anemone.wala.taintanalysis;

import com.ibm.wala.cast.ipa.callgraph.CAstCallGraphUtil;
import com.ibm.wala.cast.python.client.PythonAnalysisEngine;
import com.ibm.wala.cast.python.loader.PythonLoaderFactory;
import com.ibm.wala.cast.python.util.PythonInterpreter;
import com.ibm.wala.classLoader.Module;
import com.ibm.wala.classLoader.SourceURLModule;
import com.ibm.wala.dataflow.graph.BitVectorFramework;
import com.ibm.wala.dataflow.graph.BitVectorSolver;
import com.ibm.wala.examples.drivers.PDFTypeHierarchy;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.propagation.PropagationCallGraphBuilder;
import com.ibm.wala.ipa.callgraph.propagation.SSAContextInterpreter;
import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cfg.ExplodedInterproceduralCFG;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.WalaException;
import com.ibm.wala.util.intset.OrdinalSetMapping;
import com.ibm.wala.viz.DotUtil;
import top.anemone.wala.taintanalysis.domain.TaintVar;
import top.anemone.wala.taintanalysis.domain.TaintVarOrdinalSetMapping;
import top.anemone.wala.taintanalysis.result.PrintTraverser;
import top.anemone.wala.taintanalysis.transferfunction.TaintTransferFunctions;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;

public class TaintAnalysisDemo {
    public static void main(String[] args) throws ClassNotFoundException, IllegalAccessException, InstantiationException, CancelException, IOException, WalaException {
        Class<?> j3 = Class.forName("com.ibm.wala.cast.python3.loader.Python3LoaderFactory");
        PythonAnalysisEngine.setLoaderFactory((Class<? extends PythonLoaderFactory>) j3);
        Class<?> i3 = Class.forName("com.ibm.wala.cast.python3.util.Python3Interpreter");
        PythonInterpreter.setInterpreter((PythonInterpreter) i3.newInstance());

        String filename = "demo.py";
        Collection<Module> src = Collections.singleton(new SourceURLModule(
                TaintAnalysisDemo.class.getClassLoader().getResource(filename)));
        PythonAnalysisEngine<Void> analysisEngine = new PythonAnalysisEngine<Void>() {
            @Override
            public Void performAnalysis(PropagationCallGraphBuilder builder) throws CancelException {
                assert false;
                return null;
            }
        };
        analysisEngine.setModuleFiles(src);
        SSAPropagationCallGraphBuilder builder = (SSAPropagationCallGraphBuilder) analysisEngine.defaultCallGraphBuilder();
        CallGraph callGraph = builder.makeCallGraph(builder.getOptions());

        analysisEngine.getPointerAnalysis();
        CAstCallGraphUtil.AVOID_DUMP = false;
        CAstCallGraphUtil.dumpCG((SSAContextInterpreter) builder.getContextInterpreter(), builder.getPointerAnalysis(), callGraph);
        DotUtil.dotify(callGraph, null, PDFTypeHierarchy.DOT_FILE, "callgraph.pdf", "dot");

        ExplodedInterproceduralCFG icfg = ExplodedInterproceduralCFG.make(callGraph);
        OrdinalSetMapping<TaintVar> taintVarOrdinalSet = new TaintVarOrdinalSetMapping<>();
        TaintVar source = new TaintVar(123456789, null, null, null);
        TaintVar sink = new TaintVar(987654321, null, null, null);
        BitVectorFramework<BasicBlockInContext<IExplodedBasicBlock>, TaintVar> framework = new BitVectorFramework<>(
                icfg, new TaintTransferFunctions(taintVarOrdinalSet, callGraph, icfg, source, sink, analysisEngine.getPointerAnalysis(),new PrintTraverser()), taintVarOrdinalSet);
        BitVectorSolver<BasicBlockInContext<IExplodedBasicBlock>> solver = new BitVectorSolver<>(framework);
        solver.solve(null);
    }
}
