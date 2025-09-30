package com.financedoc.user_service.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import com.financedoc.user_service.auth.dto.response.KakaoTokenResponse;
import com.financedoc.user_service.auth.dto.response.KakaoUserInfoResponse;

import io.netty.handler.codec.http.HttpHeaderValues;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Service
public class KakaoService {

    @Value("${kakao.client-id}")
    private String clientId;

    // 콘솔에서 Client Secret 상태가 "사용함"이면 반드시 필요!
    @Value("${kakao.client-secret:}")   // 없으면 빈 문자열
    private String clientSecret;

    @Value("${kakao.redirect-uri}")
    private String redirectUri;

    private static final String KAUTH_TOKEN_URL_HOST = "https://kauth.kakao.com";
    private static final String KAPI_USER_URL_HOST   = "https://kapi.kakao.com";

    private final WebClient tokenClient  = WebClient.builder().baseUrl(KAUTH_TOKEN_URL_HOST).build();
    private final WebClient apiClient    = WebClient.builder().baseUrl(KAPI_USER_URL_HOST).build();

    /**
     * 인가코드로 Access Token 교환
     */
    public String getAccessTokenFromKakao(String code) {
        // 필수값 가드
        if (!StringUtils.hasText(clientId))     throw new IllegalStateException("kakao.client-id missing");
        if (!StringUtils.hasText(redirectUri))  throw new IllegalStateException("kakao.redirect-uri missing");
        if (!StringUtils.hasText(code))         throw new IllegalArgumentException("authorization code missing");

        // Kakao는 application/x-www-form-urlencoded 폼 바디를 요구
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", clientId);
        form.add("redirect_uri", redirectUri);
        form.add("code", code);

        // 콘솔에서 Client Secret이 "사용함"이면 반드시 포함
        if (StringUtils.hasText(clientSecret)) {
            form.add("client_secret", clientSecret);
        }

        KakaoTokenResponse token = tokenClient.post()
                .uri("/oauth/token")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError, resp ->
                        resp.bodyToMono(String.class).flatMap(body -> {
                            log.error("[Kakao Service] 4xx Error: {}", body);
                            return Mono.error(new RuntimeException("Invalid Parameter: " + body));
                        })
                )
                .onStatus(HttpStatusCode::is5xxServerError, resp ->
                        resp.bodyToMono(String.class).flatMap(body -> {
                            log.error("[Kakao Service] 5xx Error: {}", body);
                            return Mono.error(new RuntimeException("Kakao server error: " + body));
                        })
                )
                .bodyToMono(KakaoTokenResponse.class)
                .block();

        if (token == null || !StringUtils.hasText(token.getAccessToken())) {
            throw new RuntimeException("Failed to get access_token from Kakao");
        }

        // 개발 중 확인용 로그 (운영에선 토큰 로그 금지 권장)
        log.info("[Kakao Service] access_token len={}, tail=***{}",
                token.getAccessToken().length(),
                token.getAccessToken().substring(Math.max(0, token.getAccessToken().length() - 4)));
        if (StringUtils.hasText(token.getRefreshToken())) {
            log.info("[Kakao Service] refresh_token len={}", token.getRefreshToken().length());
        }
        log.debug("[Kakao Service] scope={}, id_token?={}", token.getScope(), StringUtils.hasText(token.getIdToken()));

        return token.getAccessToken();
    }

    /**
     * 사용자 정보 조회
     */
    public KakaoUserInfoResponse getUserInfo(String accessToken) {
        if (!StringUtils.hasText(accessToken)) {
            throw new IllegalArgumentException("Access token is required");
        }

        KakaoUserInfoResponse userInfo = apiClient.get()
                .uri("/v2/user/me")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                // Content-Type은 굳이 필요 없지만 붙여도 무방
                .header(HttpHeaders.CONTENT_TYPE, HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED.toString())
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError, resp ->
                        resp.bodyToMono(String.class).flatMap(body -> {
                            log.error("[Kakao Service] UserInfo 4xx Error: {}", body);
                            return Mono.error(new RuntimeException("Invalid access token or insufficient permissions: " + body));
                        })
                )
                .onStatus(HttpStatusCode::is5xxServerError, resp ->
                        resp.bodyToMono(String.class).flatMap(body -> {
                            log.error("[Kakao Service] UserInfo 5xx Error: {}", body);
                            return Mono.error(new RuntimeException("Kakao service temporarily unavailable: " + body));
                        })
                )
                .bodyToMono(KakaoUserInfoResponse.class)
                .block();

        if (userInfo == null) throw new RuntimeException("Failed to retrieve user info from Kakao");
        if (userInfo.getId() == null) throw new RuntimeException("Invalid user info: missing kakao ID");

        log.info("[Kakao Service] Kakao ID -> {}", userInfo.getId());
        if (userInfo.getKakaoAccount() == null || userInfo.getKakaoAccount().getProfile() == null) {
            log.warn("[Kakao Service] Profile information is incomplete");
        }
        return userInfo;
    }
}
