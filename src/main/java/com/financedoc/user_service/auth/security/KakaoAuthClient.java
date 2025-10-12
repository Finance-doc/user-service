package com.financedoc.user_service.auth.security;

import com.financedoc.user_service.auth.dto.response.KakaoTokenResponse;
import com.financedoc.user_service.auth.dto.response.KakaoUserInfoResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class KakaoAuthClient {

    private final RestClient rest = RestClient.builder().build();

    @Value("${kakao.client-id}")
    private String clientId;

    @Value("${kakao.client-secret:}")
    private String clientSecret; // 선택

    @Value("${kakao.redirect-uri}")
    private String defaultRedirectUri; // 미제공 시 빈 문자열 가능

    public KakaoTokenResponse exchangeCodeForToken(String code, String redirectUri) {
        String uri = "https://kauth.kakao.com/oauth/token";
        String body = form(
                "grant_type", "authorization_code",
                "client_id", clientId,
                // redirectUri가 null이면 기본값 사용
                "redirect_uri", redirectUri != null ? redirectUri : defaultRedirectUri,
                "code", code,
                // client_secret이 비어있으면 포함하지 않음
                clientSecret == null || clientSecret.isBlank() ? null : "client_secret",
                clientSecret == null || clientSecret.isBlank() ? null : clientSecret
        );

        return rest.post()
                .uri(uri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(body)
                .retrieve()
                .body(KakaoTokenResponse.class);
    }

    public KakaoUserInfoResponse getUserInfo(String kakaoAccessToken) {
        return rest.get()
                .uri("https://kapi.kakao.com/v2/user/me")
                .header("Authorization", "Bearer " + kakaoAccessToken)
                .retrieve()
                .body(KakaoUserInfoResponse.class);
    }

    private static String form(String... kvs) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < kvs.length; i += 2) {
            String k = kvs[i];
            String v = (i + 1 < kvs.length) ? kvs[i + 1] : null;
            if (k == null || v == null) continue;
            if (!sb.isEmpty()) sb.append('&');
            sb.append(encode(k)).append('=').append(encode(v));
        }
        return sb.toString();
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
