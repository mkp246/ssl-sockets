package com.manoj;

import org.apache.commons.codec.binary.Hex;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class MainSocket {
    public static final String PROXY_HOST = "web-proxy.in.hpecorp.net";
    public static final int PROXY_PORT = 8080;

    public static void main(String[] args) throws IOException, InterruptedException {
        Socket socket = new Socket("localhost", 4443);
        DataInputStream input = new DataInputStream(socket.getInputStream());
        PrintStream output = new PrintStream(socket.getOutputStream());
        byte[] tlsHelloBytes = new String(getTlsHelloRequestBytes()).getBytes(StandardCharsets.ISO_8859_1);
        output.write(tlsHelloBytes);

        byte[] bytes = new byte[64];
        while (input.available() == 0) {
            Thread.sleep(50);
        }
        int read;
        while (input.available() > 0) {
            read = input.read(bytes);
            System.out.println(Hex.encodeHexString(Arrays.copyOfRange(bytes, 0, read)));
            Arrays.fill(bytes, (byte) 0);
        }
        output.close();
        input.close();
        socket.close();
    }

    public static char[] getTlsHelloRequestBytes() {
        char[] helloBytes = {// TLS record
                0x16, // Content Type: Handshake
                0x03, 0x01, // Version: TLS 1.0
                0x00, 0x6c, // Length (use for bounds checking)
                // Handshake
                0x01, // Handshake Type: Client Hello
                0x00, 0x00, 0x68, // Length (use for bounds checking)
                0x03, 0x03, // Version: TLS 1.2
                // Random (32 bytes fixed length)
                0xb6, 0xb2, 0x6a, 0xfb, 0x55, 0x5e, 0x03, 0xd5,
                0x65, 0xa3, 0x6a, 0xf0, 0x5e, 0xa5, 0x43, 0x02,
                0x93, 0xb9, 0x59, 0xa7, 0x54, 0xc3, 0xdd, 0x78,
                0x57, 0x58, 0x34, 0xc5, 0x82, 0xfd, 0x53, 0xd1,
                0x00, // Session ID Length (skip past this much)
                0x00, 0x04, // Cipher Suites Length (skip past this much)
                0xc0, 0x2b, // NULL-MD5
                0xc0, 0x2f, // RENEGOTIATION INFO SCSV
                0x01, // Compression Methods Length (skip past this much)
                0x00, // NULL
                0x00, 0x3b, // Extensions Length (use for bounds checking)
                // Extension
                0x00, 0x00, // Extension Type: Server Name (check extension type)
                0x00, 0x0e, // Length (use for bounds checking)
                0x00, 0x0c, // Server Name Indication Length
                0x00, // Server Name Type: host_name (check server name type)
                0x00, 0x09, // Length (length of your data)
                // "localhost" (data your after)
                0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
                // Extension
                0x00, 0x0d, // Extension Type: Signature Algorithms (check extension type)
                0x00, 0x20, // Length (skip past since this is the wrong extension)
                // Data
                0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03,
                0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01,
                0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02,
                0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
                // Extension
                0x00, 0x0f, // Extension Type: Heart Beat (check extension type)
                0x00, 0x01, // Length (skip past since this is the wrong extension)
                0x01 // Mode: Peer allows to send requests
        };
        return helloBytes;
    }

    public static void httpMain() throws IOException {
        Socket socket = new Socket(PROXY_HOST, PROXY_PORT);
        DataInputStream input = new DataInputStream(socket.getInputStream());
        PrintStream output = new PrintStream(socket.getOutputStream());

        output.write("GET http://www.mocky.io/v2/5a8e94972f00005b004f2739 HTTP/1.1".getBytes());
        output.write("\r\n\r\n".getBytes());

        byte[] bytes = new byte[64];
        while (input.available() == 0) {
        }
        while (input.available() > 0) {
            input.read(bytes);
            System.out.print(new String(bytes));
            Arrays.fill(bytes, (byte) 0);
        }

        output.close();
        input.close();
        socket.close();
    }
}
