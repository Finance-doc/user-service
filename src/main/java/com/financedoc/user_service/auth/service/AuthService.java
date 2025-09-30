package com.financedoc.user_service.auth.service;

import com.financedoc.user_service.auth.dto.request.KakaoAuthRequest;
import com.financedoc.user_service.auth.dto.response.AuthTokensResponse;
import com.financedoc.user_service.auth.entity.User;
import com.financedoc.user_service.auth.repository.UserRepository;
import com.financedoc.user_service.auth.security.JwtTokenProvider;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final KakaoService kakaoService;
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    /** 카카오 로그인: 사용자 인증/가입 → 토큰 "발급만" (파싱 없음) */
    @Transactional
    public AuthTokensResponse kakaoLogin(KakaoAuthRequest request) {
        if (request == null || ((request.getCode() == null || request.getCode().isBlank())
                && (request.getKakaoAccessToken() == null || request.getKakaoAccessToken().isBlank()))) {
            throw new IllegalArgumentException("code 또는 kakaoAccessToken 중 하나는 필수입니다.");
        }

        String kakaoAccessToken = request.getKakaoAccessToken();
        if (kakaoAccessToken == null || kakaoAccessToken.isBlank()) {
            kakaoAccessToken = kakaoService.getAccessTokenFromKakao(request.getCode());
        }

        var userInfo = kakaoService.getUserInfo(kakaoAccessToken);
        User user = userService.registerOrUpdateKakaoUser(userInfo);

        Map<String, Object> claims = new HashMap<>();
        claims.put("nickname", user.getNickname());

        String accessToken = jwtTokenProvider.createAccessToken(String.valueOf(user.getId()), claims);
        String refreshToken = jwtTokenProvider.createRefreshToken(String.valueOf(user.getId()), claims);

        userService.updateRefreshToken(user, refreshToken);

        AuthTokensResponse.UserSummary summary = new AuthTokensResponse.UserSummary(
                user.getId(), user.getNickname(), user.getProfileImageUrl());

        log.info("Successfully authenticated user with kakaoId: {}", user.getKakaoId());
        return new AuthTokensResponse(accessToken, refreshToken, summary);
    }

    @Transactional
    public void deleteUser(Long userId) {
        userService.deleteUser(userId);
    }

    /**
     * 리프레시로 액세스 재발급.
     * - 게이트웨이가 refresh JWT를 검증/파싱해서 X-User-Id 헤더로 userId를 내려줌
     * - 여기서는 DB의 저장된 refreshToken과 "문자열 일치"만 확인하고 새 access 발급
     */
    @Transactional
    public String refreshAccessToken(String userIdFromGateway, String providedRefreshToken) {
        if (userIdFromGateway == null || userIdFromGateway.isBlank()) {
            throw new SecurityException("user_id가 필요합니다.");
        }
        if (providedRefreshToken == null || providedRefreshToken.isBlank()) {
            throw new IllegalArgumentException("리프레시 토큰이 필요합니다.");
        }

        User user = userRepository.findById(Long.parseLong(userIdFromGateway))
                .orElseThrow(() -> new EntityNotFoundException("사용자를 찾을 수 없습니다."));

        if (!userService.validateRefreshToken(user, providedRefreshToken)) {
            throw new SecurityException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 필요한 클레임만 재구성 (만료/발급시각 같은 표준클레임은 JWT 빌더가 새로 넣음)
        Map<String, Object> newClaims = new HashMap<>();
        newClaims.put("nickname", user.getNickname());

        return jwtTokenProvider.createAccessToken(String.valueOf(user.getId()), newClaims);
    }

    /**
     * 로그아웃.
     * - 게이트웨이가 refresh JWT를 검증/파싱해서 X-User-Id 헤더로 userId를 내려줌
     * - 여기서는 저장된 refresh와 문자열 일치만 확인 후 무효화
     */
    @Transactional
    public void logout(String userIdFromGateway, String providedRefreshToken) {
        if (userIdFromGateway == null || userIdFromGateway.isBlank()) {
            throw new SecurityException("user_id가 필요합니다.");
        }
        if (providedRefreshToken == null || providedRefreshToken.isBlank()) {
            throw new IllegalArgumentException("리프레시 토큰이 필요합니다.");
        }

        User user = userRepository.findById(Long.parseLong(userIdFromGateway))
                .orElseThrow(() -> new EntityNotFoundException("사용자를 찾을 수 없습니다."));

        if (!userService.validateRefreshToken(user, providedRefreshToken)) {
            throw new SecurityException("유효하지 않은 리프레시 토큰입니다.");
        }

        userService.logout(user);
        log.info("User logged out successfully: userId={}", userIdFromGateway);
    }
}
