package burp.polyproto.stage.framing;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Shared gRPC-Web frame parse/build. Frames are [flag][BE32 len][bytes]; flag MSB (0x80) = trailer. */
public final class GrpcWeb {

    public static final class F {
        public final int flag;
        public final byte[] data;
        F(int flag, byte[] data) { this.flag = flag; this.data = data; }
        public boolean trailer() { return (flag & 0x80) != 0; }
        public boolean compressed() { return (flag & 0x01) != 0; }
    }

    public static List<F> parse(byte[] b) {
        List<F> out = new ArrayList<>();
        int pos = 0;
        while (pos + 5 <= b.length) {
            int flag = b[pos] & 0xff;
            long len = Be32.readU32(b, pos + 1);
            pos += 5;
            if (len < 0 || pos + len > b.length) break;
            out.add(new F(flag, Arrays.copyOfRange(b, pos, (int) (pos + len))));
            pos += (int) len;
        }
        return out;
    }

    public static byte[] frame(int flag, byte[] data) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(data.length + 5);
        o.write(flag);
        Be32.writeU32(o, data.length);
        o.write(data, 0, data.length);
        return o.toByteArray();
    }

    private GrpcWeb() {}
}
