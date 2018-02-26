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

    Socket socket = new Socket(PROXY_HOST, PROXY_PORT);
    DataInputStream input = new DataInputStream(socket.getInputStream());
    PrintStream output = new PrintStream(socket.getOutputStream());

    output.write("CONNECT subscene.com:443 HTTP/1.1\r\n\r\n".getBytes());

    byte[] bytes = new byte[64];

    while (input.available() == 0) {
      Thread.sleep(50);
    }
    while (input.available() > 0) {
      input.read(bytes);
    }
    Arrays.fill(bytes, (byte) 0);

    byte[] tlsHelloBytes = new String(getTlsHelloRequestBytes()).getBytes(StandardCharsets.ISO_8859_1);
    output.write(tlsHelloBytes);

    while (input.available() == 0) {
      Thread.sleep(50);
    }

    byte[] serverHelloByte = parseAndReadHandshakeMessage(input);
    byte[] serverCertBytes = parseAndReadHandshakeMessage(input);
    byte[] serverKeyExchangeBytes = parseAndReadHandshakeMessage(input);
    byte[] serverHelloDoneBytes = parseAndReadHandshakeMessage(input);

    Arrays.fill(bytes, (byte) 0);
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

  protected static byte[] parseAndReadHandshakeMessage(DataInputStream input) throws IOException {
    byte[] bytes = new byte[5];
    input.read(bytes, 0, 5);
    int serverHelloLength = 0;
    if (bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[2] == 0x03) {
      serverHelloLength = (bytes[3] & 0xff) * 256 + (bytes[4] & 0xff);
      System.out.println("server handshake received length: " + serverHelloLength);
    }
    byte[] outputBytes = new byte[serverHelloLength];
    input.read(outputBytes);
    switch (outputBytes[0]) {
      case 0x02:
        System.out.println("handshake type sever hello");
        break;
      case 11:
        System.out.println("handshake type certificate");
        break;
      case 12:
        System.out.println("handshake type server key exchange");
        break;
      case 14:
        System.out.println("handshake type server hello done");
        break;
    }
    return outputBytes;
  }


  public static char[] getTlsHelloRequestBytes() {
    char[] helloBytes = {// TLS record
            0x16, //content type : handshake
            0x03, 0x03, //tls version 1.0
            0x00, 0xba, //record length
            0x01, //handshake protocol : client hello
            0x00, 0x00, 0xb6, //length  removed 9 bits as status request extension is removed now
            0x03, 0x03, //tls v1.2
            0xf4, 0xd7, 0x4f, 0x63, //timestamp
            0x74, 0x6d, 0x59, 0xf7, 0xc9, 0xcd, 0xe8, //rand 28 bytes
            0x0e, 0x5b, 0xc6, 0xcc, 0x13, 0x74, 0x1c, //rand 28 bytes
            0xfa, 0xf6, 0xe4, 0xb9, 0xdd, 0x75, 0x60, //rand 28 bytes
            0x9d, 0xd6, 0xe6, 0x6e, 0xfe, 0x0b, 0xdb, //rand 28 bytes
            0x00, //session Id length
            0x00, 0x1c, //cipher suite length
            0xfa, 0xfa,
            0xc0, 0x2b,
            0xc0, 0x2f,
            0xc0, 0x2c,
            0xc0, 0x30,
            0xcc, 0xa9,
            0xcc, 0xa8,
            0xc0, 0x13,
            0xc0, 0x14,
            0x00, 0x9c,
            0x00, 0x9d,
            0x00, 0x2f,
            0x00, 0x35,
            0x00, 0x0a, //ciphers ends here
            0x01,  //compression method length
            0x00, //no compression
            0x00, 0x71, //extension length 122-9
            0x4a, 0x4a, //Extension: Reserved (GREASE)
            0x00, 0x00, //(len=0)
            0xff, 0x01, //Extension: renegotiation_info
            0x00, 0x01, //(len=1)
            0x00,
            0x00, 0x00, //Extension: server_name
            0x00, 0x11, //(len=17)
            0x00, 0x0f, //Server Name list length: 15
            0x00, //Server Name Type: host_name (0)
            0x00, 0x0c, //length 12
            0x73, 0x75, 0x62, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x2e, 0x63, 0x6f, 0x6d, //subscene.com
            0x00, 0x17, //Extension: extended_master_secret
            0x00, 0x00, // (len=0)
            0x00, 0x23, //Extension: SessionTicket TLS
            0x00, 0x00, //len 0
            0x00, 0x0d, //Extension: signature_algorithms
            0x00, 0x14, //(len=20)
            0x00, 0x12, //sig hash algo len 18
            0x04, 0x03,
            0x08, 0x04,
            0x04, 0x01,
            0x05, 0x03,
            0x08, 0x05,
            0x05, 0x01,
            0x08, 0x06,
            0x06, 0x01,
            0x02, 0x01,
            0x00, 0x12, //Extension: signed_certificate_timestamp
            0x00, 0x00, //(len=0)
            0x00, 0x10, //Extension: application_layer_protocol_negotiation
            0x00, 0x0e, //(len=14)
            0x00, 0x0c, //ALPN Extension Length: 12
            0x02,//            ALPN string length: 2
            0x68, 0x32, //ALPN Next Protocol: h2
            0x08, // ALPN string length: 8
            0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // ALPN Next Protocol: http/1.1
            0x75, 0x50, //ext  channel id
            0x00, 0x00, //len 0
            0x00, 0x0b, //ext :ec point format
            0x00, 0x02, //len 2
            0x01, //EC point formats Length: 1
            0x00, // EC point format: uncompressed (0)
            0x00, 0x0a, //ext: supported_groups
            0x00, 0x0a, //len 10
            0x00, 0x08, //Supported Groups List Length: 8
            0xda, 0xda,
            0x00, 0x1d,
            0x00, 0x17,
            0x00, 0x18,
            0x6a, 0x6a, //Extension: Reserved (GREASE)
            0x00, 0x01, //(len=1)
            0x00
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
