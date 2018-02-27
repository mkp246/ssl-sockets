package com.manoj;

import java.util.Arrays;

public class ECDHParams {
  public byte curveType;
  public byte[] curveName;
  public byte[] publicKey;
  public byte sigHashAlgoHash;
  public byte sigHashAlgoSignature;
  public byte[] signature;

  public static ECDHParams parseMessage(byte[] serverKeyExchangeBytes) {
    ECDHParams ecdhParams = new ECDHParams();
    if (serverKeyExchangeBytes[0] != 0x0c) {
      System.out.println("not server key exchange");
      return null;
    }
    int currentIndex = 4;
    ecdhParams.curveType = serverKeyExchangeBytes[currentIndex++];
    ecdhParams.curveName = new byte[]{serverKeyExchangeBytes[currentIndex++], serverKeyExchangeBytes[currentIndex++]};
    int pubkeyLength = serverKeyExchangeBytes[currentIndex++] & 0xff;
    ecdhParams.publicKey = Arrays.copyOfRange(serverKeyExchangeBytes, currentIndex, currentIndex + pubkeyLength);
    currentIndex += pubkeyLength;
    ecdhParams.sigHashAlgoHash = serverKeyExchangeBytes[currentIndex++];
    ecdhParams.sigHashAlgoSignature = serverKeyExchangeBytes[currentIndex++];
    int sigLength = ((serverKeyExchangeBytes[currentIndex++] & 0xff) << 8) + serverKeyExchangeBytes[currentIndex++];
    ecdhParams.signature = Arrays.copyOfRange(serverKeyExchangeBytes, currentIndex, currentIndex + sigLength);
    return ecdhParams;
  }
}
