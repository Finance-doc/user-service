package com.financedoc.user_service.auth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;

@Service
public class TokenService {

    private final Algorithm alg;
    private final long accessValidityMs;   // jwt.access-token-validity
    private final long refreshValidityMs;  // jwt.refresh-token-validity
    private final String issuer;           // jwt.issuer

    public TokenService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-validity}") long accessValidityMs,
            @Value("${jwt.refresh-token-validity}") long refreshValidityMs,
            @Value("${jwt.issuer}") String issuer
    ) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("jwt.secret is required");
        }
        this.alg = Algorithm.HMAC256(secret);
        this.accessValidityMs = accessValidityMs;
        this.refreshValidityMs = refreshValidityMs;
        this.issuer = issuer;
    }

    public String createAccessToken(Long userId) {
        Instant now = Instant.now();
        return JWT.create()
                .withIssuer(issuer)
                .withSubject(String.valueOf(userId))
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusMillis(accessValidityMs)))
                .sign(alg);
    }

    public String createRefreshToken(Long userId, String jti) {
        Instant now = Instant.now();
        return JWT.create()
                .withIssuer(issuer)
                .withSubject(String.valueOf(userId))
                .withJWTId(jti)
                .withClaim("typ", "refresh")
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusMillis(refreshValidityMs)))
                .sign(alg);
    }

    public DecodedJWT verify(String token) {
        return JWT.require(alg)
                .withIssuer(issuer)
                .build()
                .verify(token);
    }
}
