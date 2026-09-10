import java.nio.file.*;
import org.objectweb.asm.*;

/** Generates only known test fixtures, never reads or loads target bytecode. */
public class Generate implements Opcodes {
    public static void main(String[] args) throws Exception {
        Path out=Paths.get(args[0]); Files.createDirectories(out.resolve("p"));
        ClassWriter w=new ClassWriter(ClassWriter.COMPUTE_FRAMES|ClassWriter.COMPUTE_MAXS);
        w.visit(V1_8,ACC_PUBLIC,"p/Renamed",null,"java/lang/Object",null);
        w.visitField(ACC_PUBLIC|ACC_STATIC,"data","[Ljava/lang/String;",null,null).visitEnd();
        MethodVisitor m=w.visitMethod(ACC_STATIC,"<clinit>","()V",null,null); m.visitCode();
        m.visitInsn(ICONST_2);m.visitTypeInsn(ANEWARRAY,"java/lang/String");
        m.visitInsn(DUP);m.visitInsn(ICONST_0);m.visitLdcInsn("pooled\u0000value");m.visitInsn(AASTORE);
        m.visitInsn(DUP);m.visitInsn(ICONST_1);m.visitLdcInsn("\ud800");m.visitInsn(AASTORE);
        m.visitFieldInsn(PUTSTATIC,"p/Renamed","data","[Ljava/lang/String;");m.visitInsn(RETURN);m.visitMaxs(0,0);m.visitEnd();w.visitEnd();
        Files.write(out.resolve("p/Renamed.class"),w.toByteArray());
        w=new ClassWriter(ClassWriter.COMPUTE_FRAMES|ClassWriter.COMPUTE_MAXS);
        w.visit(V1_8,ACC_PUBLIC,"Numeric",null,"java/lang/Object",null);
        m=w.visitMethod(ACC_PUBLIC|ACC_STATIC,"number","()I",null,null);m.visitCode();
        m.visitIntInsn(SIPUSH,0x2dc7);m.visitIntInsn(SIPUSH,0xcf);m.visitInsn(IAND);m.visitInsn(IRETURN);m.visitMaxs(0,0);m.visitEnd();
        m=w.visitMethod(ACC_PUBLIC|ACC_STATIC,"overflow","()J",null,null);m.visitCode();
        m.visitLdcInsn(Long.MIN_VALUE);m.visitLdcInsn(-1L);m.visitInsn(LDIV);m.visitInsn(LRETURN);m.visitMaxs(0,0);m.visitEnd();
        m=w.visitMethod(ACC_PUBLIC|ACC_STATIC,"negativeZero","()F",null,null);m.visitCode();
        m.visitLdcInsn(-0.0f);m.visitLdcInsn(2.0f);m.visitInsn(FMUL);m.visitInsn(FRETURN);m.visitMaxs(0,0);m.visitEnd();
        m=w.visitMethod(ACC_PUBLIC|ACC_STATIC,"branch","(Z)I",null,null);m.visitCode();
        Label end=new Label();m.visitVarInsn(ILOAD,0);m.visitJumpInsn(IFEQ,end);
        m.visitLdcInsn(7);m.visitLdcInsn(5);m.visitInsn(IXOR);m.visitInsn(IRETURN);
        m.visitLabel(end);m.visitLdcInsn(10);m.visitLdcInsn(3);m.visitInsn(ISUB);m.visitInsn(IRETURN);m.visitMaxs(0,0);m.visitEnd();
        m=w.visitMethod(ACC_PUBLIC|ACC_STATIC,"division","()I",null,null);m.visitCode();
        Label start=new Label(),stop=new Label(),handler=new Label();m.visitTryCatchBlock(start,stop,handler,"java/lang/ArithmeticException");
        m.visitLabel(start);m.visitInsn(ICONST_1);m.visitInsn(ICONST_0);m.visitInsn(IDIV);m.visitLabel(stop);m.visitInsn(IRETURN);
        m.visitLabel(handler);m.visitInsn(POP);m.visitLdcInsn(42);m.visitInsn(IRETURN);m.visitMaxs(0,0);m.visitEnd();
        w.visitEnd();Files.write(out.resolve("Numeric.class"),w.toByteArray());
    }
}
