package top.anemone.wala.taintanalysis;

import com.ibm.wala.cast.python.client.PythonAnalysisEngine;
import com.ibm.wala.cast.python.loader.PythonLoaderFactory;
import com.ibm.wala.cast.python.module.PyScriptModule;
import com.ibm.wala.cast.python.util.PythonInterpreter;
import com.ibm.wala.classLoader.Module;
import com.ibm.wala.classLoader.SourceURLModule;
import com.ibm.wala.dataflow.graph.BitVectorFramework;
import com.ibm.wala.dataflow.graph.BitVectorSolver;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.propagation.PropagationCallGraphBuilder;
import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cfg.ExplodedInterproceduralCFG;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.intset.OrdinalSetMapping;
import top.anemone.wala.taintanalysis.domain.TaintVar;
import top.anemone.wala.taintanalysis.domain.TaintVarOrdinalSetMapping;
import top.anemone.wala.taintanalysis.result.PrintTraverser;
import top.anemone.wala.taintanalysis.result.TaintGraphTraverser;
import top.anemone.wala.taintanalysis.transferfunction.TaintTransferFunctions;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;

public class TaintAnalysis {
    public void analysis(Collection<Module> src, TaintGraphTraverser resultProcessor) throws CancelException, IOException, ClassNotFoundException, IllegalAccessException, InstantiationException {
        Class<?> j3 = Class.forName("com.ibm.wala.cast.python3.loader.Python3LoaderFactory");
        PythonAnalysisEngine.setLoaderFactory((Class<? extends PythonLoaderFactory>) j3);
        Class<?> i3 = Class.forName("com.ibm.wala.cast.python3.util.Python3Interpreter");
        PythonInterpreter.setInterpreter((PythonInterpreter) i3.newInstance());
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
        ExplodedInterproceduralCFG icfg = ExplodedInterproceduralCFG.make(callGraph);
        OrdinalSetMapping<TaintVar> taintVarOrdinalSet = new TaintVarOrdinalSetMapping<>();
        TaintVar source = new TaintVar(123456789, null, null, null);
        TaintVar sink = new TaintVar(987654321, null, null, null);
        BitVectorFramework<BasicBlockInContext<IExplodedBasicBlock>, TaintVar> framework = new BitVectorFramework<>(
                icfg, new TaintTransferFunctions(taintVarOrdinalSet, callGraph, icfg, source, sink, builder.getPointerAnalysis(), resultProcessor), taintVarOrdinalSet);
        BitVectorSolver<BasicBlockInContext<IExplodedBasicBlock>> solver = new BitVectorSolver<>(framework);
        solver.solve(null);
    }

    public static void main(String[] args) throws ClassNotFoundException, CancelException, InstantiationException, IllegalAccessException, IOException {
        String filename = "demo.py";
        Collection<Module> src = Collections.singleton(new PyScriptModule(
                TaintAnalysis.class.getClassLoader().getResource(filename)));
        new TaintAnalysis().analysis(src, new PrintTraverser());
    }
}
