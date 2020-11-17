package top.anemone.wala.taintanalysis;

import com.ibm.wala.util.collections.HashMapFactory;
import com.ibm.wala.util.debug.Assertions;
import com.ibm.wala.util.debug.UnimplementedError;
import com.ibm.wala.util.intset.OrdinalSetMapping;

import java.util.*;
import java.util.stream.Stream;

public class MyOrdinalSetMapping<T> implements OrdinalSetMapping<T> {

    /** A mapping from object to Integer */
    private final HashMap<T, Integer> map = HashMapFactory.make();
    private final List<T> array = new ArrayList<>();

    public MyOrdinalSetMapping() {
    }

    @Override
    public T getMappedObject(int n) throws NoSuchElementException {
        if (n>=array.size()){
            throw new IllegalArgumentException("invalid n: " + n);
        }
        return array.get(n);
    }

    @Override
    public int getMappedIndex(Object o) {
        if (map.get(o) == null) {
            return -1;
        }
        return map.get(o);
    }

    @Override
    public boolean hasMappedIndex(Object o) {
        return map.get(o) != null;
    }

    @Override
    public Iterator<T> iterator() {
        return map.keySet().iterator();
    }

    @Override
    public Stream<T> stream() {
        return map.keySet().stream();
    }

    @Override
    public int add(Object o) throws UnimplementedError {
        T t;
        try{
            t = (T) o;
        } catch (ClassCastException e){
            throw new UnimplementedError(e.toString());
        }
        array.add(t);
        map.put(t, array.size()-1);
        return array.size()-1;
    }

    @Override
    public int getMaximumIndex() {
        return array.size() - 1;
    }

    @Override
    public int getSize() {
        return map.size();
    }
}
