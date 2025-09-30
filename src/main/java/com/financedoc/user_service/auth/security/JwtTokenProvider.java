package com.financedoc.user_service.auth.security;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import javax.crypto.SecretKey;

@Slf4j
@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")                   // 게이트웨이와 합의: HS256이면 같은 시크릿 공유, RS256이면 개인키/공개키 분리
    private String secret;

    @Value("${jwt.access-token-validity}")
    private long accessTokenValidityMs;

    @Value("${jwt.refresh-token-validity}")
    private long refreshTokenValidityMs;

    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Decoders.BASE64.decode(ensureBase64(secret));
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    private String ensureBase64(String value) {
        boolean looksBase64 = value != null && value.matches("^[A-Za-z0-9+/=]+$");
        return looksBase64 ? value
                : java.util.Base64.getEncoder().encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** access 토큰 발급: sub = user_id (+ 필요 시 roles 등 claim 추가) */
    public String createAccessToken(String userId, Map<String, Object> extraClaims) {
        Map<String, Object> claims = (extraClaims == null) ? new HashMap<>() : new HashMap<>(extraClaims);
        claims.putIfAbsent("user_id", userId);   // 과도기 호환용
        claims.put("category", "access");

        Date now = new Date();
        Date exp = new Date(now.getTime() + accessTokenValidityMs);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userId)              // ★ 핵심: sub = user_id
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(secretKey)             // HS256 기준. RS256이면 privateKey로 sign
                .compact();
    }

    /** refresh 토큰 발급 */
    public String createRefreshToken(String userId, Map<String, Object> extraClaims) {
        Map<String, Object> claims = (extraClaims == null) ? new HashMap<>() : new HashMap<>(extraClaims);
        claims.putIfAbsent("user_id", userId);
        claims.put("category", "refresh");

        Date now = new Date();
        Date exp = new Date(now.getTime() + refreshTokenValidityMs);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userId)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(secretKey)
                .compact();
    }
}
