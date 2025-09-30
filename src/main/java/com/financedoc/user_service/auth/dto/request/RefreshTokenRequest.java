package com.financedoc.user_service.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Schema(description = "액세스 토큰 갱신 요청")
public class RefreshTokenRequest {
    @Schema(description = "리프레시 토큰", requiredMode = Schema.RequiredMode.REQUIRED)
    private String refreshToken;
}
