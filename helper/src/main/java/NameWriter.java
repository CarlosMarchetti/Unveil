import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.*;

/** Mechanical remapper: all selection, inheritance and risk analysis is Python. */
public final class NameWriter {
    static String member(String owner,String name,String descriptor) {
        return owner+"\u0000"+name+"\u0000"+descriptor;
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=3) throw new IllegalArgumentException("input.jar names.bin changes.zip");
        final Map<String,String> classes=new HashMap<>(), methods=new HashMap<>(), fields=new HashMap<>();
        List<String> entries=new ArrayList<>();
        try(DataInputStream in=new DataInputStream(new BufferedInputStream(Files.newInputStream(Paths.get(args[1]))))) {
            if(in.readInt()!=0x554e4e31) throw new IOException("Invalid names plan");
            int n=in.readInt();
            for(int i=0;i<n;i++) classes.put(SafeWriter.str(in),SafeWriter.str(in));
            for(Map<String,String> map:Arrays.asList(methods,fields)) {
                n=in.readInt();
                for(int i=0;i<n;i++) {
                    String owner=SafeWriter.str(in), name=SafeWriter.str(in), desc=SafeWriter.str(in);
                    map.put(member(owner,name,desc),SafeWriter.str(in));
                }
            }
            n=in.readInt(); for(int i=0;i<n;i++) entries.add(SafeWriter.str(in));
            if(in.read()!=-1) throw new IOException("Trailing names plan data");
        }
        Remapper remapper=new Remapper() {
            @Override public String map(String name) {return classes.getOrDefault(name,name);}
            @Override public String mapMethodName(String owner,String name,String descriptor) {
                return methods.getOrDefault(member(owner,name,descriptor),name);
            }
            @Override public String mapFieldName(String owner,String name,String descriptor) {
                return fields.getOrDefault(member(owner,name,descriptor),name);
            }
        };
        boolean failed=false;
        try(ZipFile input=new ZipFile(args[0]); ZipOutputStream output=new ZipOutputStream(Files.newOutputStream(Paths.get(args[2])))) {
            for(String entry:entries) {
                try {
                    byte[] bytes;
                    ZipEntry e=input.getEntry(entry); if(e==null) throw new IOException("Class entry absent");
                    try(InputStream in=input.getInputStream(e)) {bytes=SafeWriter.bytes(in);}
                    ClassReader reader=new ClassReader(bytes);
                    // Frames are remapped along with their referenced types. No
                    // flow or stack effects change, so frames/maxs stay valid.
                    ClassWriter writer=new ClassWriter(0);
                    reader.accept(new ClassRemapper(writer,remapper),0);
                    byte[] result=writer.toByteArray();
                    SafeWriter.verify(result);
                    output.putNextEntry(new ZipEntry(entry)); output.write(result); output.closeEntry();
                    SafeWriter.status("OK",entry,"");
                } catch(Exception | LinkageError ex) {
                    failed=true;
                    String message=String.valueOf(ex.getMessage());
                    SafeWriter.status("ERROR",entry,ex.getClass().getSimpleName()+": "+message.substring(0,Math.min(message.length(),500)));
                }
            }
        }
        if(failed) System.exit(2); // Python discards the whole transaction.
    }
}
