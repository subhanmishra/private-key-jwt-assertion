package com.subhanmishra.oidc.privkeyjwt.service;

import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class TokenService {

    public String createToken() {

        Map<String, Object> claims = new HashMap<>();
        claims.put("custom_claim", "custom_claim_value");

        String clientId = "test-prv-key-jwt-client";
        String tokenEndpoint = "http://localhost:8080/realms/subhanmishra/protocol/openid-connect/token";

        Instant now = Instant.now();
        return Jwts.builder()
                .setIssuer(clientId)
                .setSubject(clientId)
                .setAudience(tokenEndpoint)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(5L, ChronoUnit.MINUTES)))
//                .setClaims(claims)
                .signWith(getSignKey())
                .compact();
    }

    private Key getSignKey() {

        String pathPKCS12 = "classpath:keystore/keystore.p12";
        String pwdPKCS12 = "password";


        InputStream fm = null;
        try {
            File file = ResourceUtils.getFile(pathPKCS12);
            fm = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        KeyStore keystore = null;
        Key key = null;
        Certificate cert = null;
        try {
            keystore = KeyStore.getInstance("PKCS12");
            keystore.load(fm, pwdPKCS12.toCharArray());
            key = keystore.getKey(keystore.aliases().nextElement(), pwdPKCS12.toCharArray());
            cert = keystore.getCertificate(keystore.aliases().nextElement());
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
        PublicKey publicKey = cert.getPublicKey();
        KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        return rsaPrivateKey;
    }
}
