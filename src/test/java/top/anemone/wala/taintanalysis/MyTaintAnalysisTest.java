package top.anemone.wala.taintanalysis;

import com.ibm.wala.cast.python.client.PythonAnalysisEngine;
import com.ibm.wala.cast.python.global.SystemPath;
import com.ibm.wala.cast.python.loader.PythonLoaderFactory;
import com.ibm.wala.cast.python.module.PyLibURLModule;
import com.ibm.wala.cast.python.module.PyScriptModule;
import com.ibm.wala.cast.python.util.PythonInterpreter;
import com.ibm.wala.classLoader.Module;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.WalaException;
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import top.anemone.wala.taintanalysis.result.PathTraverser;
import top.anemone.wala.taintanalysis.result.PrintTraverser;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

public class MyTaintAnalysisTest extends TestCase {

    @Before
    public void before() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        Class<?> j3 = Class.forName("com.ibm.wala.cast.python3.loader.Python3LoaderFactory");
        PythonAnalysisEngine.setLoaderFactory((Class<? extends PythonLoaderFactory>) j3);
        Class<?> i3 = Class.forName("com.ibm.wala.cast.python3.util.Python3Interpreter");
        PythonInterpreter.setInterpreter((PythonInterpreter) i3.newInstance());
        SystemPath.getInstance().unlockAppPath();

    }

    @Test
    public void testIntra() throws CancelException, IOException, ClassNotFoundException, IllegalAccessException, InstantiationException, WalaException {

        String filename = "intra.py";
        Collection<Module> src = new HashSet<>();
        src.add(new PyScriptModule(TaintAnalysis.class.getClassLoader().getResource(filename)));
        for (File f: Utils.getLibsFromDir("pylibs")){
            src.add(new PyLibURLModule(f));
        }
        PathTraverser pathTraverser=new PathTraverser();
        Configuration configuration = new Configuration();
        configuration.loadPrimitiveConfigs();
        new TaintAnalysis().analysis(src,configuration,pathTraverser);

        assertEquals(pathTraverser.getPaths().size(), 1);
        /*
        intra.py [8:0] -> [8:12]
        intra.py [6:2] -> [6:15]
        intra.py [6:2] -> [6:15]
        intra.py [5:12] -> [5:38]
         */
        assertTrue(4<pathTraverser.getPaths().get(0).size()-1 );
    }

    @Test
    public void testInter1() throws CancelException, IOException, IllegalAccessException, InstantiationException, ClassNotFoundException, WalaException {
        String filename = "inter1.py";
        Collection<Module> src = new HashSet<>();
        src.add(new PyScriptModule(TaintAnalysis.class.getClassLoader().getResource(filename)));
        for (File f: Utils.getLibsFromDir("pylibs")){
            src.add(new PyLibURLModule(f));
        }
        Configuration configuration = new Configuration(true);
        configuration.loadPrimitiveConfigs();
        PathTraverser pathTraverser=new PathTraverser();
        new TaintAnalysis().analysis(src,configuration,pathTraverser);
        assertEquals(pathTraverser.getPaths().size(), 1);
        /*
        inter1.py [22:10] -> [22:17]
        inter1.py [22:10] -> [22:15]
        inter1.py [21:4] -> [21:33]
        inter1.py [8:0] -> [9:27]
        <Code body of function Lscript inter1.py/getxxx>
        <Code body of function Lscript inter1.py/getxxx>
        inter1.py [21:4] -> [21:33]
        inter1.py [19:0] -> [19:3]
        inter1.py [17:0] -> [17:3]
        inter1.py [15:12] -> [15:38]
         */
        assertTrue(11> pathTraverser.getPaths().get(0).size()-1 );
    }

    @Test
    public void testInter2() throws CancelException, IOException, IllegalAccessException, InstantiationException, ClassNotFoundException, WalaException {
        String filename = "inter2.py";
        Collection<Module> src = new HashSet<>();
        src.add(new PyScriptModule(TaintAnalysis.class.getClassLoader().getResource(filename)));
        for (File f: Utils.getLibsFromDir("pylibs")){
            src.add(new PyLibURLModule(f));
        }
        Configuration configuration = new Configuration();
        configuration.loadPrimitiveConfigs();
        PathTraverser pathTraverser=new PathTraverser();
        new TaintAnalysis().analysis(src,configuration,pathTraverser);

        assertEquals(pathTraverser.getPaths().size(), 1);
        /*
        inter1.py [22:10] -> [22:17]
        inter1.py [22:10] -> [22:15]
        inter1.py [21:4] -> [21:33]
        inter1.py [8:0] -> [9:27]
        <Code body of function Lscript inter1.py/getxxx>
        <Code body of function Lscript inter1.py/getxxx>
        inter1.py [21:4] -> [21:33]
        inter1.py [19:0] -> [19:3]
        inter1.py [17:0] -> [17:3]
        inter1.py [15:12] -> [15:38]
         */
        assertTrue(9< pathTraverser.getPaths().get(0).size()-1 );
    }

    @Test
    public void testInter3() throws CancelException, IOException, IllegalAccessException, InstantiationException, ClassNotFoundException, WalaException {
        String filename = "inter3.py";

        Collection<Module> src = new HashSet<>();
        src.add(new PyScriptModule(TaintAnalysis.class.getClassLoader().getResource(filename)));
        for (File f: Utils.getLibsFromDir("pylibs")){
            src.add(new PyLibURLModule(f));
        }
        PathTraverser pathTraverser=new PathTraverser();

        Configuration configuration = new Configuration();
        configuration.loadPrimitiveConfigs();
        new TaintAnalysis().analysis(src,configuration,pathTraverser);

        assertEquals(pathTraverser.getPaths().size(), 1);
        /*
        inter3.py [9:4] -> [9:16]
        <Code body of function Lscript inter3.py/thread>
        <Code body of function Lscript inter3.py/thread>
        inter3.py [18:0] -> [18:36]
        inter3.py [16:12] -> [16:38]
         */
        assertTrue(5< pathTraverser.getPaths().get(0).size()-1 );
    }

    @Test
    public void testInter4() throws CancelException, IOException, IllegalAccessException, InstantiationException, ClassNotFoundException, WalaException {
        String filename = "inter4.py";

        Collection<Module> src = new HashSet<>();
        src.add(new PyScriptModule(TaintAnalysis.class.getClassLoader().getResource(filename)));
        for (File f: Utils.getLibsFromDir("pylibs")){
            src.add(new PyLibURLModule(f));
        }
        PathTraverser pathTraverser=new PathTraverser();

        Configuration configuration = new Configuration();
        configuration.loadPrimitiveConfigs();
        new TaintAnalysis().analysis(src,configuration,pathTraverser);

        assertEquals(pathTraverser.getPaths().size(), 1);
        /*
        inter3.py [9:4] -> [9:16]
        <Code body of function Lscript inter3.py/thread>
        <Code body of function Lscript inter3.py/thread>
        inter3.py [18:0] -> [18:36]
        inter3.py [16:12] -> [16:38]
         */
        assertTrue(5< pathTraverser.getPaths().get(0).size()-1 );
    }

    @Test
    public void testInter5() throws CancelException, IOException, IllegalAccessException, InstantiationException, ClassNotFoundException, WalaException {
        String filename = "inter5.py";

        Collection<Module> src = new HashSet<>();
        src.add(new PyScriptModule(TaintAnalysis.class.getClassLoader().getResource(filename)));
        for (File f: Utils.getLibsFromDir("pylibs")){
            src.add(new PyLibURLModule(f));
        }
        PathTraverser pathTraverser=new PathTraverser();

        Configuration configuration = new Configuration(true);
        configuration.loadPrimitiveConfigs();
        new TaintAnalysis().analysis(src,configuration,pathTraverser);

        assertEquals(pathTraverser.getPaths().size(), 1);
        /*
        inter3.py [9:4] -> [9:16]
        <Code body of function Lscript inter3.py/thread>
        <Code body of function Lscript inter3.py/thread>
        inter3.py [18:0] -> [18:36]
        inter3.py [16:12] -> [16:38]
         */
        assertTrue(5< pathTraverser.getPaths().get(0).size()-1 );
    }
}