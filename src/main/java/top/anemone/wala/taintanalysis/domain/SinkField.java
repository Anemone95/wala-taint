package top.anemone.wala.taintanalysis.domain;

import java.util.Objects;

public class SinkField extends Sink{
    public String field;


    public SinkField(String clazz, String field) {
        this.clazz = clazz;
        this.field = field;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        SinkField sinkField = (SinkField) o;
        return Objects.equals(field, sinkField.field);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), field);
    }

    public static void main(String[] args) {
        Sink s1=new SinkField("A","B");
        Sink s2=new SinkField("A","B");
        s2.clazz="A";
        System.out.println(s1.hashCode());
        System.out.println(s2.hashCode());
        System.out.println(s1.equals(s2));
    }
}
