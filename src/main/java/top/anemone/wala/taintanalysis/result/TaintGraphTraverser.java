package top.anemone.wala.taintanalysis.result;

import top.anemone.wala.taintanalysis.domain.Statement;

public interface TaintGraphTraverser {
    void traverse(Statement from, Statement to);
}
