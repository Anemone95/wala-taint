package top.anemone.wala.taintanalysis.result;


import top.anemone.wala.taintanalysis.domain.Statement;

import java.util.LinkedList;
import java.util.List;

public class PrintTraverser implements TaintGraphTraverser{
    List<Statement> searchPath = new LinkedList<>();
    public boolean printPath(Statement from, Statement to) {
        if (from.equals(to)){
            List<Statement> foundPath = new LinkedList<>(searchPath);

            for (Statement v: searchPath) {
                if (v.taintVar.inst!=null){
                    System.out.println(v.taintVar.getPosition());
                } else if (v.method!=null){
                    System.out.println(v.taintVar.method);
                }
            }
            return true;
        }
        boolean found=false;
        for (Statement preVar: to.taintVar.getPrevStatements()){
            if (!searchPath.contains(preVar)){
                searchPath.add(preVar);
                found|= printPath(from, preVar);
                searchPath.remove(preVar);
            }
        }
        return found;

    }

    @Override
    public void traverse(Statement from, Statement to) {
        printPath(from, to);
    }
}
