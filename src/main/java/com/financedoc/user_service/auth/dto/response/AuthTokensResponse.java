package com.financedoc.user_service.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "JWT 토큰 및 사용자 정보 응답")
public class AuthTokensResponse {

    @Schema(description = "액세스 토큰", example = "eyJhbGciOiJIUzI1NiJ9...")
    private String accessToken;

    @Schema(description = "리프레시 토큰", example = "eyJhbGciOiJIUzI1NiJ9...")
    private String refreshToken;

    @Schema(description = "사용자 정보 요약")
    private UserSummary user;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Schema(description = "사용자 요약 정보 DTO")
    public static class UserSummary {
        @Schema(description = "사용자 ID", example = "1")
        private Long id;

        @Schema(description = "닉네임", example = "최은비")
        private String nickname;

        @Schema(description = "프로필 이미지 URL", example = "https://...")
        private String profileImageUrl;
    }
}
