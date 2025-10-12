package com.financedoc.user_service.auth.controller;

import com.financedoc.user_service.auth.dto.request.KakaoAuthRequest;
import com.financedoc.user_service.auth.dto.request.RefreshTokenRequest;
import com.financedoc.user_service.auth.dto.response.AuthTokensResponse;
import com.financedoc.user_service.auth.dto.response.MessageResponse;
import com.financedoc.user_service.auth.dto.response.NewAccessTokenResponse;
import com.financedoc.user_service.auth.dto.response.UserResponse;
import com.financedoc.user_service.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
@Tag(name = "Auth", description = "카카오 로그인 및 토큰 발급 API (검증/파싱은 게이트웨이 담당)")
@Slf4j
public class AuthController {

    private final AuthService authService;

    /** 카카오 콜백: 로그인/회원가입 처리 후 토큰 '발급만' 수행 */
    @GetMapping("/kakao")
    public ResponseEntity<Void> kakaoCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @RequestParam(name = "error_description", required = false) String errorDescription,
            HttpServletRequest request   // ★ 추가
    ) {
        log.info("Kakao callback code={}, state={}, error={}, error_description={}",
                code, state, error, errorDescription);

        if (error != null) {
            return ResponseEntity.status(302)
                    .header("Location", "/login?error=" + error)
                    .build();
        }
        if (!StringUtils.hasText(code)) {
            return ResponseEntity.status(302)
                    .header("Location", "/login?error=code_missing")
                    .build();
        }

        // ★ authorize 때와 '완전히 같은' redirect_uri 생성 (쿼리 제거)
        String redirectUri = ServletUriComponentsBuilder.fromRequestUri(request)
                .replaceQuery(null)
                .build()
                .toUriString(); // -> http://localhost:8080/user/auth/kakao

        KakaoAuthRequest req = new KakaoAuthRequest();
        req.setCode(code);
        req.setKakaoAccessToken(null);

        // ★ 동일 redirect_uri로 토큰 교환
        AuthTokensResponse tokens = authService.kakaoLogin(req, redirectUri);

        // (선택) 쿠키 세팅 — 운영 HTTPS에선 secure(true) 권장
        ResponseCookie accessCookie = ResponseCookie.from("access_token", tokens.getAccessToken())
                .httpOnly(true).path("/").sameSite("Lax")
                .build();

        ResponseEntity.BodyBuilder resp = ResponseEntity.status(302)
                .header("Set-Cookie", accessCookie.toString());

        if (StringUtils.hasText(tokens.getRefreshToken())) {
            ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", tokens.getRefreshToken())
                    .httpOnly(true).path("/").sameSite("Lax")
                    .maxAge(14L * 24 * 60 * 60)
                    .build();
            resp.header("Set-Cookie", refreshCookie.toString());
        }

        String redirectTo = (StringUtils.hasText(state) && state.startsWith("/")) ? state : "/";
        return resp.header("Location", redirectTo).build();
    }

    /** 모바일 등에서 직접 로그인 요청: 토큰 '발급만' */
    @PostMapping("/kakao")
    @Operation(summary = "카카오 로그인", description = "인가 코드 또는 카카오 액세스 토큰으로 로그인/회원가입을 수행하고 JWT를 발급(검증/파싱은 게이트웨이)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "성공", content = @Content(schema = @Schema(implementation = AuthTokensResponse.class)))
    })
    public ResponseEntity<AuthTokensResponse> kakaoLoginFromMobile(@RequestBody KakaoAuthRequest request) {
        AuthTokensResponse response = authService.kakaoLogin(request);
        return ResponseEntity.ok(response);
    }

    /** 현재 사용자 정보 조회 — 게이트웨이가 X-User-Id 주입 */
    @GetMapping("/me")
    @Operation(summary = "현재 사용자 정보 조회", description = "게이트웨이가 주입한 사용자 식별자(X-User-Id) 기반 조회")
    @ApiResponse(responseCode = "200", description = "성공", content = @Content(schema = @Schema(implementation = UserResponse.class)))
    public ResponseEntity<UserResponse> getCurrentUser(@RequestHeader("X-User-Id") Long userId) {
        return ResponseEntity.ok(authService.getCurrentUser(userId));
    }

    /** 회원 탈퇴 — X-User-Id 기반 */
    @DeleteMapping("/me")
    @Operation(summary = "회원 탈퇴", description = "현재 로그인한 사용자의 계정을 삭제")
    @ApiResponse(responseCode = "204", description = "탈퇴 성공")
    public ResponseEntity<Void> deleteUser(@RequestHeader("X-User-Id") Long userId) {
        authService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

    /** 액세스 토큰 재발급 — 게이트웨이가 refresh를 검증/파싱해도, 서버에서 한 번 더 확인(권장) */
    @PostMapping("/refresh")
    @Operation(summary = "액세스 토큰 갱신", description = "리프레시 토큰으로 새 액세스 토큰 발급(서버는 typ=refresh, jti 화이트리스트, sub 일치 검증)")
    @ApiResponse(responseCode = "200", description = "갱신 성공", content = @Content(schema = @Schema(implementation = NewAccessTokenResponse.class)))
    public ResponseEntity<NewAccessTokenResponse> refresh(
            @RequestBody RefreshTokenRequest request
    ) {
        String newAccessToken = authService.refreshAccessToken(request.getRefreshToken());
        return ResponseEntity.ok(new NewAccessTokenResponse(newAccessToken));
    }

    /** 로그아웃 — 전달된 refresh의 jti만 폐기 */
    @PostMapping("/logout")
    @Operation(summary = "로그아웃", description = "리프레시 토큰 무효화")
    @ApiResponse(responseCode = "200", description = "로그아웃 성공", content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    public ResponseEntity<MessageResponse> logout(
            @RequestHeader("X-User-Id") Long userId,
            @RequestBody RefreshTokenRequest request
    ) {
        authService.logout(userId, request.getRefreshToken());
        return ResponseEntity.ok(new MessageResponse("로그아웃되었습니다."));
    }
}