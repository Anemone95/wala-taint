package top.anemone.wala.taintanalysis.domain;

import java.util.Objects;

public class Sink {
    public String clazz;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Sink sink = (Sink) o;
        return Objects.equals(clazz, sink.clazz);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clazz);
    }
}
