package top.anemone.wala.taintanalysis;

import top.anemone.wala.taintanalysis.domain.Sink;
import top.anemone.wala.taintanalysis.domain.SinkField;
import top.anemone.wala.taintanalysis.domain.SinkMethod;

import java.util.Collection;
import java.util.HashSet;

public class Configuration {
    private Collection<String> sources;
    private Collection<SinkField> sinkFields;
    private Collection<SinkMethod> sinkMethods;
    private Collection<String> sanitizers;
    private boolean debug;

    public boolean isDebug() {
        return debug;
    }

    public Configuration (){
        this(false);
    }
    public Configuration (boolean debug){
        sources=new HashSet<>();
        sinkFields=new HashSet<>();
        sinkMethods=new HashSet<>();
        sanitizers=new HashSet<>();
        this.debug=debug;
    }

    public Collection<String> getSources() {
        return sources;
    }

    public void addSource(String source) {
        this.sources.add(source);
    }

    public void addSources(Collection<String> sources) {
        this.sources.addAll(sources);
    }

    public Collection<SinkMethod> getSinkMethods() {
        return sinkMethods;
    }
    public Collection<SinkField> getSinkFields() {
        return sinkFields;
    }

    public void addSink(Sink sink) {
        if (sink instanceof SinkField){
            this.sinkFields.add((SinkField) sink);
        } else if (sink instanceof SinkMethod){
            this.sinkMethods.add((SinkMethod) sink);
        }
    }

    public Collection<String> getSanitizers() {
        return sanitizers;
    }

    public void addSanitizers(Collection<String> sanitizers) {
        this.sanitizers.addAll(sanitizers);
    }
    public void addSanitizer(String sanitizer) {
        this.sanitizers.add(sanitizer);
    }

    public void loadPrimitiveConfigs() {
        sources.add("Lwalataint/function/source_func");
        sources.add("Lwalataint/field/source_field");
        addSink(new SinkMethod("Lwalataint/function/sink_func","do",1));
        addSink(new SinkField("Lwalataint","sink_field"));
    }
}
