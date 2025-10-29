package com.financedoc.user_service.auth.dto.request;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class TestLoginReq {
    private String username;
    private String password;
}
