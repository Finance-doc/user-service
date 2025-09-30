package com.financedoc.user_service.auth.service;

import com.financedoc.user_service.auth.dto.response.KakaoUserInfoResponse;
import com.financedoc.user_service.auth.entity.User;
import com.financedoc.user_service.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    @Value("${kakao.admin-key}")
    private String kakaoAdminKey;
    private final UserRepository userRepository;

    @Transactional
    public User registerOrUpdateKakaoUser(KakaoUserInfoResponse userInfo) {
        Optional<User> existingUserOpt = userRepository.findByKakaoId(userInfo.getId());

        if (existingUserOpt.isPresent()) {
            User existingUser = existingUserOpt.get();
            return existingUser;
        } else {
            User newUser = User.createFromKakao(
                    userInfo.getId(),
                    userInfo.getKakaoAccount() != null ? userInfo.getKakaoAccount().getEmail() : null,
                    userInfo.getKakaoAccount() != null && userInfo.getKakaoAccount().getProfile() != null
                            ? userInfo.getKakaoAccount().getProfile().getNickName() : null,
                    userInfo.getKakaoAccount() != null && userInfo.getKakaoAccount().getProfile() != null
                            ? userInfo.getKakaoAccount().getProfile().getProfileImageUrl() : null
            );
            log.info("Created new user with kakaoId: {}", newUser.getKakaoId());

            User user = userRepository.save(newUser);

            return user;
        }
    }

    @Transactional(readOnly = true)
    public User getUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    @Transactional
    public void updateRefreshToken(User user, String refreshToken) {
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public boolean validateRefreshToken(User user, String refreshToken) {
        return refreshToken.equals(user.getRefreshToken());
    }

    @Transactional
    public void logout(User user) {
        user.setRefreshToken(null);
        userRepository.save(user);
    }

    @Transactional
    public void deleteUser(Long userId) {
        User user = getUserById(userId);

        unlinkKakaoAccount(user.getKakaoId());
        userRepository.delete(user);
    }

    private void unlinkKakaoAccount(Long kakaoId) {
        String url = "https://kapi.kakao.com/v1/user/unlink";
        String body = "target_id_type=user_id&target_id=" + kakaoId;

        WebClient.create(url).post()
                .header(HttpHeaders.AUTHORIZATION, "KakaoAK " + kakaoAdminKey)
                .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                .bodyValue(body)
                .retrieve()
                .bodyToMono(String.class)
                .doOnSuccess(response -> log.info("Kakao unlink success for kakaoId={}: {}", kakaoId, response))
                .doOnError(error -> log.error("Kakao unlink failed for kakaoId={}: {}", kakaoId, error.getMessage()))
                .block();
    }
}
