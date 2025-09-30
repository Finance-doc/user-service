package com.financedoc.user_service.auth.controller;

import com.financedoc.user_service.auth.dto.request.KakaoAuthRequest;
import com.financedoc.user_service.auth.dto.request.RefreshTokenRequest;
import com.financedoc.user_service.auth.dto.response.AuthTokensResponse;
import com.financedoc.user_service.auth.dto.response.MessageResponse;
import com.financedoc.user_service.auth.dto.response.NewAccessTokenResponse;
import com.financedoc.user_service.auth.dto.response.UserResponse;
import com.financedoc.user_service.auth.security.CustomUserDetails;
import com.financedoc.user_service.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user/auth")
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
            @RequestParam(name = "error_description", required = false) String errorDescription
    ) {
        log.info("Kakao callback code={}, state={}, error={}, error_description={}",
                code, state, error, errorDescription);

        if (error != null) {
            return ResponseEntity.status(302)
                    .header("Location", "/login?error=" + error)
                    .build();
        }
        if (!org.springframework.util.StringUtils.hasText(code)) {
            return ResponseEntity.status(302)
                    .header("Location", "/login?error=code_missing")
                    .build();
        }

        KakaoAuthRequest req = new KakaoAuthRequest();
        req.setCode(code);
        req.setKakaoAccessToken(null);

        AuthTokensResponse tokens = authService.kakaoLogin(req);

        // (선택) 쿠키 세팅 — 운영 HTTPS에선 .secure(true) 권장
        ResponseCookie accessCookie = ResponseCookie.from("access_token", tokens.getAccessToken())
                .httpOnly(true).path("/").sameSite("Lax")
                .build();

        ResponseEntity.BodyBuilder resp = ResponseEntity.status(302)
                .header("Set-Cookie", accessCookie.toString());

        if (org.springframework.util.StringUtils.hasText(tokens.getRefreshToken())) {
            ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", tokens.getRefreshToken())
                    .httpOnly(true).path("/").sameSite("Lax")
                    .maxAge(14L * 24 * 60 * 60)
                    .build();
            resp.header("Set-Cookie", refreshCookie.toString());
        }

        String redirectTo = (org.springframework.util.StringUtils.hasText(state) && state.startsWith("/")) ? state : "/";
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

    /** 현재 사용자 정보 조회 — SecurityContext는 필터가 X-User-Id로 세팅 */
    @GetMapping("/me")
    @Operation(summary = "현재 사용자 정보 조회", description = "게이트웨이가 주입한 사용자 식별자 기반으로 현재 사용자 정보를 조회")
    @ApiResponse(responseCode = "200", description = "성공", content = @Content(schema = @Schema(implementation = UserResponse.class)))
    public ResponseEntity<UserResponse> getCurrentUser(@AuthenticationPrincipal CustomUserDetails userDetails) {
        UserResponse response = new UserResponse(
                userDetails.getId(),
                userDetails.getNickname(),
                userDetails.getProfileImageUrl()
        );
        return ResponseEntity.ok(response);
    }

    /** 회원 탈퇴 */
    @DeleteMapping("/me")
    @Operation(summary = "회원 탈퇴", description = "현재 로그인한 사용자의 계정을 삭제")
    @ApiResponse(responseCode = "204", description = "탈퇴 성공")
    public ResponseEntity<Void> deleteUser(@AuthenticationPrincipal CustomUserDetails userDetails) {
        authService.deleteUser(userDetails.getId());
        return ResponseEntity.noContent().build();
    }

    /** 액세스 토큰 재발급 — 게이트웨이가 refresh 토큰을 검증/파싱해 X-User-Id 주입 */
    @PostMapping("/refresh")
    @Operation(summary = "액세스 토큰 갱신", description = "게이트웨이가 검증한 리프레시 토큰 컨텍스트에서 X-User-Id로 새 액세스 토큰 발급")
    @ApiResponse(responseCode = "200", description = "갱신 성공", content = @Content(schema = @Schema(implementation = NewAccessTokenResponse.class)))
    public ResponseEntity<NewAccessTokenResponse> refresh(
            @RequestHeader("X-User-Id") String userId,     // ★ 게이트웨이가 넣어준 식별자
            @RequestBody RefreshTokenRequest request
    ) {
        String newAccessToken = authService.refreshAccessToken(userId, request.getRefreshToken());
        return ResponseEntity.ok(new NewAccessTokenResponse(newAccessToken));
    }

    /** 로그아웃 — 게이트웨이가 검증/파싱했고 여기선 DB의 refresh 문자열만 검증 */
    @PostMapping("/logout")
    @Operation(summary = "로그아웃", description = "게이트웨이가 검증한 컨텍스트에서 리프레시 토큰 무효화")
    @ApiResponse(responseCode = "200", description = "로그아웃 성공", content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    public ResponseEntity<MessageResponse> logout(
            @RequestHeader("X-User-Id") String userId,     // ★ 게이트웨이가 넣어준 식별자
            @RequestBody RefreshTokenRequest request
    ) {
        authService.logout(userId, request.getRefreshToken());
        return ResponseEntity.ok(new MessageResponse("로그아웃되었습니다."));
    }
}