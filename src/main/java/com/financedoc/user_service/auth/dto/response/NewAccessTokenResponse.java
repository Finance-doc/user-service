package com.financedoc.user_service.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class NewAccessTokenResponse {
    private String accessToken;
}

