package com.financedoc.user_service.auth.controller;

import com.financedoc.user_service.auth.dto.request.TestLoginReq;
import com.financedoc.user_service.auth.dto.response.AuthTokensResponse;
import com.financedoc.user_service.auth.entity.User;
import com.financedoc.user_service.auth.repository.UserRepository;
import com.financedoc.user_service.auth.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/test")
public class UserTestController {

    private final UserRepository userRepository;
    private final TokenService tokenService;

    public String test(
            @RequestHeader(value = "X-User-Id") String userId
    ){
        return "User Service Test OK :: X-User-Id = "+userId;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody TestLoginReq testLoginReq){
        User user = userRepository.findByUserId(testLoginReq.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.getPassword().equals(testLoginReq.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        String accessToken = tokenService.createAccessToken(user.getId());
        String refreshToken = tokenService.createRefreshToken(user.getId(), accessToken);
        AuthTokensResponse response = new AuthTokensResponse(
                accessToken,
                refreshToken,
                new AuthTokensResponse.UserSummary(user.getId(), user.getNickname(), user.getProfileImageUrl())
        );

        return ResponseEntity.ok(response);
    }



}