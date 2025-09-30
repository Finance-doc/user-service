package com.financedoc.user_service.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "카카오 로그인 요청 DTO")
public class KakaoAuthRequest {

    @Schema(description = "카카오 인가 코드", example = "AbCdEf...", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String code;

    @Schema(description = "카카오 액세스 토큰", example = "kakao_access_token...", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String kakaoAccessToken;
}