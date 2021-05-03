package top.anemone.wala.taintanalysis;

import com.ibm.wala.fixpoint.BitVectorVariable;
import com.ibm.wala.util.intset.OrdinalSetMapping;
import top.anemone.wala.taintanalysis.domain.Statement;
import top.anemone.wala.taintanalysis.domain.TaintVar;

import java.io.File;
import java.util.*;

public class Utils {
    static public class GetTaintRet {
        public TaintVar taintVar;
        public Statement fromField;

        public GetTaintRet(TaintVar taintVar, Statement fromField) {
            this.taintVar = taintVar;
            this.fromField = fromField;
        }
    }

    // FIXME 这里应该同时获取get的路径
    public static GetTaintRet getTaint(TaintVar taintVar, OrdinalSetMapping<TaintVar> taintVars, BitVectorVariable rhs) {
        return getTaint(taintVar, null, taintVars, rhs, new LinkedList<>(), 0);
    }

    public static GetTaintRet getTaint(TaintVar taintVar, Statement prevStatement, OrdinalSetMapping<TaintVar> taintVars, BitVectorVariable rhs, List<Statement> book, int depth) {
        int idx = taintVars.getMappedIndex(taintVar);
        boolean hasTaint = idx != -1 && rhs.get(idx);
        if (hasTaint) {
            // 如果taintVar不是map中的定义var，将其取出使 taintVar.prev=mapVar
            if (!new Statement(taintVar).equals(new Statement(taintVars.getMappedObject(idx)))) {
                taintVar.addPrevStatement(new Statement(taintVars.getMappedObject(idx)));
            }
            return new GetTaintRet(taintVar, prevStatement);
        }
        for (Statement field : taintVar.fields.values()) {
            if (!book.contains(field)) {
                book.add(field);
                GetTaintRet taint = getTaint(field.taintVar, field, taintVars, rhs, book, depth + 1);
                book.remove(field);
                if (taint != null) {
                    taint.fromField = field;
                    return taint;
                }
            }
        }
        return null;
    }

    public static List<File> getLibsFromDir(String path) {
        List<File> allFiles = new LinkedList<>();
        LinkedList<File> queue = new LinkedList<>();
        queue.add(new File(path));
        File firstFile;
        while (!queue.isEmpty()){
            firstFile=queue.removeFirst();
            for (File filePath: firstFile.listFiles()) {
                if (filePath.isDirectory()) {
                    queue.add(filePath);
                } else if (filePath.toString().endsWith(".py")){
                    allFiles.add(filePath);
                }
            }
        }

        return allFiles;
    }
}
