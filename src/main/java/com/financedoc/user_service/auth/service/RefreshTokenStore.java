package com.financedoc.user_service.auth.service;

import java.time.Instant;

public interface RefreshTokenStore {
    void save(long userId, String jti, Instant expiresAt);
    boolean exists(long userId, String jti);
    void rotate(long userId, String oldJti, String newJti, Instant newExpiresAt);
    void revoke(long userId, String jti);
    void revokeAll(long userId);
}
