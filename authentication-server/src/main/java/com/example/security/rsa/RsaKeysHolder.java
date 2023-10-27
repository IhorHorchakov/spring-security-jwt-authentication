package com.example.security.rsa;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@AllArgsConstructor
@Getter
public class RsaKeysHolder {
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;
}
