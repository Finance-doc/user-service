package com.financedoc.user_service.auth.dto.response;

import lombok.Getter;

@Getter
public class UserResponse {
    private final Long userId;
    private final String nickname;
    private final String profileImageUrl;

    public UserResponse(Long userId, String nickname, String profileImageUrl) {
        this.userId = userId;
        this.nickname = nickname;
        this.profileImageUrl = profileImageUrl;
    }
}

