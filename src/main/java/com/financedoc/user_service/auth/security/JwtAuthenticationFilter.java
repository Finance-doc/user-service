package com.financedoc.user_service.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.financedoc.user_service.auth.entity.User;
import com.financedoc.user_service.auth.repository.UserRepository;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String USER_ID_HEADER = "X-User-Id"; // 게이트웨이가 주입

    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // CORS 프리플라이트는 통과
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            // 게이트웨이가 넣어준 user_id만 신뢰
            String userId = request.getHeader(USER_ID_HEADER);

            // 정책에 따라 없으면 401로 끊고 싶다면 아래 주석 해제
            // if (!StringUtils.hasText(userId)) {
            //     response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing X-User-Id");
            //     return;
            // }

            if (StringUtils.hasText(userId)
                    && SecurityContextHolder.getContext().getAuthentication() == null) {

                User user = loadUserByUserId(userId);
                if (user != null) {
                    UserDetails userDetails = new CustomUserDetails(user);
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    log.warn("User not found for userId={}", userId);
                    // 필요 시 401로 끊기
                    // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not found");
                    // return;
                }
            }
        } catch (Exception e) {
            log.error("Gateway user authentication failed: {}", e.getMessage(), e);
            SecurityContextHolder.clearContext();
            // 필요 시 막기
            // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
            // return;
        }

        chain.doFilter(request, response);
    }

    /**
     * userId가 PK(Long/UUID)일 수도, 별도 컬럼(String)일 수도 있으니
     * 두 경우를 모두 커버. 프로젝트 스키마에 맞춰 한 가지로 고정해도 됨.
     */
    private User loadUserByUserId(String userId) {
        // 1) PK가 Long인 경우
        try {
            long id = Long.parseLong(userId);
            return userRepository.findById(id).orElse(null);
        } catch (NumberFormatException ignore) {
            // 2) userId가 문자열/UUID 컬럼인 경우: findByUserId(...) 사용
            //    ⚠️ 리포지토리에 메서드가 없다면 추가하세요:
            //    Optional<User> findByUserId(String userId);
            try {
                return userRepository.findByUserId(userId).orElse(null);
            } catch (NoSuchMethodError | UnsupportedOperationException e) {
                log.error("UserRepository.findByUserId(String) is missing. " +
                        "Add it or switch to your repository method.");
                return null;
            }
        }
    }
}