package com.financedoc.user_service.auth.entity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
@Entity
@Table(name = "users")
public class User {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "kakao_id", nullable = false, unique = true)
    private Long kakaoId;

    @Column(name="user_id", unique = true, nullable = false)
    private String userId;

    @Column(name = "email")
    private String email;

    @Column(name = "nickname")
    private String nickname;

    @Column(name = "avatar_url")
    private String profileImageUrl;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @Column(name = "refresh_token")
    private String refreshToken;

    public static User createFromKakao(Long kakaoId, String email, String nickname, String profileImageUrl) {
        User u = new User();
        u.kakaoId = kakaoId;
        u.email = email;
        u.nickname = nickname;
        u.profileImageUrl = profileImageUrl;
        return u;
    }

    public void updateNickname(String nickname) { this.nickname = nickname; }
}

