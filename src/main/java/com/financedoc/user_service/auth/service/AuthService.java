package com.financedoc.user_service.auth.service;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.financedoc.user_service.auth.security.KakaoAuthClient;
import com.financedoc.user_service.auth.dto.request.KakaoAuthRequest;
import com.financedoc.user_service.auth.dto.response.*;
import com.financedoc.user_service.auth.dto.response.KakaoUserInfoResponse.KakaoAccount;
import com.financedoc.user_service.auth.dto.response.KakaoUserInfoResponse.KakaoAccount.Profile;
import com.financedoc.user_service.auth.entity.User;
import com.financedoc.user_service.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final KakaoAuthClient kakao;
    private final UserRepository users;
    private final TokenService tokens;          // HS256 발급/검증
    private final RefreshTokenStore refresh;    // jti 화이트리스트

    // === 로그인 (오버로드) ===
    @Transactional
    public AuthTokensResponse kakaoLogin(KakaoAuthRequest req) {
        return kakaoLogin(req, null); // redirectUri 미지정 시 client 기본값 사용
    }

    @Transactional
    public AuthTokensResponse kakaoLogin(KakaoAuthRequest req, String redirectUriMaybeNull) {
        // 1) 카카오 access token 확보
        String kakaoAccessToken = null;
        if (StringUtils.hasText(req.getKakaoAccessToken())) {
            kakaoAccessToken = req.getKakaoAccessToken();
        } else if (StringUtils.hasText(req.getCode())) {
            KakaoTokenResponse token = kakao.exchangeCodeForToken(req.getCode(), redirectUriMaybeNull);
            kakaoAccessToken = token.getAccessToken();
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Either 'code' or 'kakaoAccessToken' is required");
        }

        // 2) 카카오 유저 조회
        KakaoUserInfoResponse info = kakao.getUserInfo(kakaoAccessToken);
        if (info == null || info.getId() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Failed to fetch Kakao user");
        }

        // 3) upsert(주의: userId NOT NULL 제약)
        String nickname = extractNickname(info);
        String profile = extractProfileImage(info);
        String email = Optional.ofNullable(info.getKakaoAccount()).map(KakaoAccount::getEmail).orElse(null);

        User user = users.findByKakaoId(info.getId())
                .map(u -> {
                    boolean changed = false;
                    if (nickname != null && !nickname.equals(u.getNickname())) { u.setNickname(nickname); changed = true; }
                    if (profile != null && !Objects.equals(profile, u.getProfileImageUrl())) { u.setProfileImageUrl(profile); changed = true; }
                    if (email != null && !Objects.equals(email, u.getEmail())) { u.setEmail(email); changed = true; }
                    if (changed) u.setUpdatedAt(Instant.now());
                    return changed ? users.save(u) : u;
                })
                .orElseGet(() -> users.save(
                        User.builder()
                                .kakaoId(info.getId())
                                .userId(generateUserId())   // ★ NOT NULL/UNIQUE
                                .email(email)
                                .nickname(nickname)
                                .profileImageUrl(profile)
                                .createdAt(Instant.now())
                                .updatedAt(Instant.now())
                                .build()
                ));

        // 4) 토큰 발급 + 리프레시 저장
        String access = tokens.createAccessToken(user.getId());
        String jti = UUID.randomUUID().toString();
        String refreshToken = tokens.createRefreshToken(user.getId(), jti);
        refresh.save(user.getId(), jti, Instant.now().plus(14, ChronoUnit.DAYS));

        return new AuthTokensResponse(
                access,
                refreshToken,
                new AuthTokensResponse.UserSummary(user.getId(), user.getNickname(), user.getProfileImageUrl())
        );
    }

    // === 액세스 토큰 재발급(검증 + sub 일치) ===
    @Transactional(readOnly = true)
    public String refreshAccessToken(Long userIdFromHeader, String refreshToken) {
        DecodedJWT jwt = tokens.verify(refreshToken);
        if (!"refresh".equals(jwt.getClaim("typ").asString())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Not a refresh token");
        }
        long sub = parseUserId(jwt);
        if (sub != userIdFromHeader) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token subject mismatch");
        }
        String jti = jwt.getId();
        if (!refresh.exists(sub, jti)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh invalidated");
        }
        return tokens.createAccessToken(sub);
    }

    // === 로그아웃(해당 refresh jti만 폐기) ===
    @Transactional
    public void logout(Long userIdFromHeader, String refreshToken) {
        DecodedJWT jwt = tokens.verify(refreshToken);
        if (!"refresh".equals(jwt.getClaim("typ").asString())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Not a refresh token");
        }
        long sub = parseUserId(jwt);
        if (sub != userIdFromHeader) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token subject mismatch");
        }
        refresh.revoke(sub, jwt.getId());
    }

    // === 현재 사용자 조회 ===
    @Transactional(readOnly = true)
    public UserResponse getCurrentUser(Long userId) {
        User u = users.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        return new UserResponse(u.getId(), u.getNickname(), u.getProfileImageUrl());
    }

    // === 회원 탈퇴 ===
    @Transactional
    public void deleteUser(Long userId) {
        if (!users.existsById(userId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
        }
        users.deleteById(userId);
        refresh.revokeAll(userId);
    }

    // --- helpers ---
    private static String generateUserId() {
        return "U" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }
    private static long parseUserId(DecodedJWT jwt) {
        try { return Long.parseLong(jwt.getSubject()); }
        catch (NumberFormatException e) { throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid subject"); }
    }
    private static String extractNickname(KakaoUserInfoResponse info) {
        return Optional.ofNullable(info.getKakaoAccount())
                .map(KakaoAccount::getProfile).map(Profile::getNickName)
                .orElseGet(() -> Optional.ofNullable(info.getProperties()).map(m -> m.get("nickname")).orElse(null));
    }
    private static String extractProfileImage(KakaoUserInfoResponse info) {
        return Optional.ofNullable(info.getKakaoAccount())
                .map(KakaoAccount::getProfile).map(Profile::getProfileImageUrl)
                .orElseGet(() -> Optional.ofNullable(info.getProperties()).map(m -> m.get("profile_image")).orElse(null));
    }
}