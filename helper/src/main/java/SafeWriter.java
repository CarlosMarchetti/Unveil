import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;
import org.objectweb.asm.util.CheckClassAdapter;

/** Trusted mechanical writer only. Never resolves or defines target classes. */
public final class SafeWriter {
    static String str(DataInputStream in) throws IOException {
        int n = in.readInt();
        if (n < 0 || n > 16777216) throw new IOException("Invalid string length");
        if ((n & 1)!=0) throw new IOException("Odd UTF-16 length");
        char[] chars=new char[n/2];
        for(int i=0;i<chars.length;i++) chars[i]=in.readChar();
        return new String(chars);
    }
    static byte[] bytes(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] b = new byte[65536]; int n;
        while ((n = in.read(b)) != -1) out.write(b,0,n);
        return out.toByteArray();
    }
    static class Edit {
        String method, desc; int start, end; InsnList replacement;
    }
    static Map<String,List<Edit>> plan(Path path) throws IOException {
        Map<String,List<Edit>> all = new LinkedHashMap<>();
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(Files.newInputStream(path),65536))) {
            if (in.readInt() != 0x554e5631) throw new IOException("Invalid plan");
            int count = in.readInt();
            for (int c=0;c<count;c++) {
                String entry = str(in); List<Edit> edits = new ArrayList<>();
                all.put(entry, edits); int size = in.readInt();
                for (int j=0;j<size;j++) {
                    Edit e = new Edit(); e.method=str(in); e.desc=str(in);
                    e.start=in.readInt(); e.end=in.readInt(); e.replacement=new InsnList();
                    int n=in.readInt();
                    for (int k=0;k<n;k++) {
                        int t=in.readUnsignedByte(); Object v;
                        switch (t) {
                            case 'I': v=in.readInt(); break;
                            case 'J': v=in.readLong(); break;
                            case 'F': v=Float.intBitsToFloat(in.readInt()); break;
                            case 'D': v=Double.longBitsToDouble(in.readLong()); break;
                            case 'S': v=str(in); break;
                            case 'N': e.replacement.add(new InsnNode(Opcodes.ACONST_NULL)); continue;
                            case 'P':
                                int op=in.readUnsignedByte();
                                if (op!=Opcodes.POP && op!=Opcodes.POP2) throw new IOException("Forbidden replacement opcode");
                                e.replacement.add(new InsnNode(op)); continue;
                            default: throw new IOException("Bad replacement type");
                        }
                        e.replacement.add(new LdcInsnNode(v));
                    }
                    edits.add(e);
                }
            }
            if (in.read()!=-1) throw new IOException("Trailing plan bytes");
        }
        return all;
    }
    static void verify(byte[] b) throws Exception {
        ClassReader r=new ClassReader(b);
        // checkDataFlow=true uses BasicVerifier, not SimpleVerifier/Class.forName.
        r.accept(new CheckClassAdapter(new ClassWriter(0),true),0);
        ClassNode cn=new ClassNode(); r.accept(cn,0);
        for (MethodNode m:cn.methods) {
            if ((m.access & (Opcodes.ACC_ABSTRACT|Opcodes.ACC_NATIVE))==0)
                new Analyzer<BasicValue>(new BasicVerifier()).analyze(cn.name,m);
        }
    }
    static byte[] rewrite(byte[] b, List<Edit> edits) throws Exception {
        ClassReader r=new ClassReader(b); ClassNode cn=new ClassNode(); r.accept(cn,0);
        Map<String,List<Edit>> byMethod=new HashMap<>();
        Set<String> signatures=new HashSet<>(), annotations=new HashSet<>();
        for (Edit e:edits) {
            if(e.method.equals("@metadata")) {
                if(e.replacement.size()!=1 || !(e.replacement.getFirst() instanceof LdcInsnNode)) throw new IOException("Bad metadata plan");
                String value=(String)((LdcInsnNode)e.replacement.getFirst()).cst;
                if(e.desc.equals("signature")) signatures.add(value);
                else if(e.desc.equals("invisible-annotation")) annotations.add(value);
                else throw new IOException("Unknown metadata operation");
            } else byMethod.computeIfAbsent(e.method+e.desc,k->new ArrayList<>()).add(e);
        }
        if(signatures.contains(cn.signature)) cn.signature=null;
        cleanAnnotations(cn.invisibleAnnotations,annotations);
        for(FieldNode f:cn.fields) {
            if(signatures.contains(f.signature)) f.signature=null;
            cleanAnnotations(f.invisibleAnnotations,annotations);
        }
        for(MethodNode m:cn.methods) {
            if(signatures.contains(m.signature)) m.signature=null;
            cleanAnnotations(m.invisibleAnnotations,annotations);
        }
        for (MethodNode m:cn.methods) {
            List<Edit> es=byMethod.remove(m.name+m.desc); if(es==null) continue;
            List<AbstractInsnNode> ops=new ArrayList<>();
            Set<LabelNode> barriers=new HashSet<>();
            for(TryCatchBlockNode t:m.tryCatchBlocks) {barriers.add(t.start); barriers.add(t.end); barriers.add(t.handler);}
            for(AbstractInsnNode i:m.instructions) {
                if(i.getOpcode()>=0) ops.add(i);
                if(i instanceof JumpInsnNode) barriers.add(((JumpInsnNode)i).label);
                if(i instanceof TableSwitchInsnNode) {barriers.add(((TableSwitchInsnNode)i).dflt);barriers.addAll(((TableSwitchInsnNode)i).labels);}
                if(i instanceof LookupSwitchInsnNode) {barriers.add(((LookupSwitchInsnNode)i).dflt);barriers.addAll(((LookupSwitchInsnNode)i).labels);}
            }
            es.sort((a,z)->Integer.compare(z.start,a.start)); int previous=ops.size();
            for(Edit e:es) {
                if(e.start<0 || e.end>previous || e.start>=e.end) throw new IOException("Overlapping/out of range edit");
                AbstractInsnNode first=ops.get(e.start), last=ops.get(e.end-1);
                if(first!=last)
                    for(AbstractInsnNode i=first.getNext(); i!=null && i!=last; i=i.getNext())
                        if(i instanceof FrameNode || barriers.contains(i)) throw new IOException("Edit crosses control-flow boundary");
                m.instructions.insertBefore(first,e.replacement);
                for(int j=e.start;j<e.end;j++) m.instructions.remove(ops.get(j));
                previous=e.start;
            }
        }
        if(!byMethod.isEmpty()) throw new IOException("Missing method");
        // Changes preserve the type/stack state at every old frame. Preserve
        // frames (including exact external types), relocate labels, recompute maxs.
        // No getCommonSuperClass and no class loading are needed.
        ClassWriter w=new ClassWriter(r,ClassWriter.COMPUTE_MAXS); cn.accept(w);
        byte[] out=w.toByteArray(); verify(out); return out;
    }
    static void cleanAnnotations(List<AnnotationNode> nodes,Set<String> bad) {
        if(nodes!=null) nodes.removeIf(a->bad.contains(a.desc));
    }
    static void status(String kind,String entry,String reason) {
        System.out.println(kind+"\t"+Base64.getEncoder().encodeToString(entry.getBytes(StandardCharsets.UTF_8))+"\t"+
            Base64.getEncoder().encodeToString(reason.getBytes(StandardCharsets.UTF_8)));
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=4) throw new IllegalArgumentException("rewrite|verify input.jar plan.bin output-changes.zip");
        Map<String,List<Edit>> all=plan(Paths.get(args[2]));
        try(ZipFile input=new ZipFile(args[1]); ZipOutputStream output=new ZipOutputStream(Files.newOutputStream(Paths.get(args[3])))) {
            for(Map.Entry<String,List<Edit>> row:all.entrySet()) {
                String entry=row.getKey();
                try {
                    ZipEntry ze=input.getEntry(entry); if(ze==null) throw new IOException("Missing entry");
                    byte[] b; try(InputStream in=input.getInputStream(ze)) {b=bytes(in);}
                    if(args[0].equals("verify")) verify(b);
                    else if(args[0].equals("rewrite")) {
                        b=rewrite(b,row.getValue());
                        output.putNextEntry(new ZipEntry(entry)); output.write(b); output.closeEntry();
                    } else throw new IOException("Invalid mode");
                    status("OK",entry,"");
                } catch(Exception | LinkageError ex) {
                    // No candidate bytes are published before successful checks.
                    String message=String.valueOf(ex.getMessage());
                    if(message.length()>500) message=message.substring(0,500);
                    status("ERROR",entry,ex.getClass().getSimpleName()+": "+message+" "+Arrays.toString(Arrays.copyOf(ex.getStackTrace(),Math.min(5,ex.getStackTrace().length))));
                }
            }
        }
    }
}
