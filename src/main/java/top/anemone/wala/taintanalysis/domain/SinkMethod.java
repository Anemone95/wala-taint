package top.anemone.wala.taintanalysis.domain;

import java.util.Objects;

public class SinkMethod extends Sink {
    public String method;
    public int paramIdx;


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        SinkMethod that = (SinkMethod) o;
        return paramIdx == that.paramIdx &&
                Objects.equals(method, that.method);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), method, paramIdx);
    }

    public SinkMethod(String clazz, String method, int paramIdx) {
        this.clazz = clazz;
        this.method = method;
        this.paramIdx = paramIdx;
    }
}
