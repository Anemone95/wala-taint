package top.anemone.wala.taintanalysis;


import java.util.LinkedList;
import java.util.List;

public class PrintUtil {
    List<TypedTaintVar> path = new LinkedList<>();

    public boolean printPath(TaintVar from, TaintVar to) {
        if (from.equals(to)){
            for (TypedTaintVar v:path) {
                if (v.taintVar.inst!=null){
                    System.out.println(v.taintVar.getPosition());
                } else if (v.method!=null){
                    System.out.println(v.taintVar.method);
                }
            }
            return true;
        }
        boolean found=false;
        for (TaintVar nextVar: from.propagateTaintVars){
            TypedTaintVar nextTypedVar=new TypedTaintVar(nextVar);
            if (!path.contains(nextTypedVar)){
                path.add(nextTypedVar);
                found|= printPath(nextVar, to);
                path.remove(nextTypedVar);
            }
        }
        return found;
    }
}
