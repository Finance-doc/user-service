package com.financedoc.user_service.auth.service;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryRefreshTokenStore implements RefreshTokenStore {
    private final Map<Long, Map<String, Instant>> mem = new ConcurrentHashMap<>();

    @Override
    public void save(long userId, String jti, Instant expiresAt) {
        mem.computeIfAbsent(userId, k -> new ConcurrentHashMap<>()).put(jti, expiresAt);
    }

    @Override
    public boolean exists(long userId, String jti) {
        Instant exp = Optional.ofNullable(mem.get(userId)).map(m -> m.get(jti)).orElse(null);
        return exp != null && Instant.now().isBefore(exp);
    }

    @Override
    public void rotate(long userId, String oldJti, String newJti, Instant newExpiresAt) {
        Map<String, Instant> map = mem.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());
        map.remove(oldJti);
        map.put(newJti, newExpiresAt);
    }

    @Override
    public void revoke(long userId, String jti) {
        Optional.ofNullable(mem.get(userId)).ifPresent(m -> m.remove(jti));
    }

    @Override
    public void revokeAll(long userId) {
        mem.remove(userId);
    }
}