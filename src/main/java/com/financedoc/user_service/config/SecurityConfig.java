package com.financedoc.user_service.config;

import com.financedoc.user_service.auth.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CORS & CSRF
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())

                // H2 콘솔 등
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))

                // 세션 미사용
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 인가 규칙
                .authorizeHttpRequests(auth -> auth
                        // 프리플라이트
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 로그인/발급은 서비스에서 처리(게이트웨이는 검증만): 필요 경로만 남기세요
                        .requestMatchers(
                                "/user/auth/kakao",
                                "/user/auth/login",
                                "/user/auth/refresh",
                                "/user/auth/logout"
                        ).permitAll()

                        // 헬스/테스트
                        .requestMatchers("/", "/user/test", "/actuator/health", "/error").permitAll()

                        // Swagger (있으면)
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()

                        // 나머지 보호
                        .anyRequest().authenticated()
                )

                // ★ 게이트웨이가 넣은 X-User-Id로 SecurityContext 세팅
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOriginPatterns(List.of("*")); // 운영에선 특정 도메인으로 제한 권장
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("*"));
        cfg.setExposedHeaders(List.of("Authorization", "X-User-Id")); // ← 필요 시 노출
        cfg.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }
}
