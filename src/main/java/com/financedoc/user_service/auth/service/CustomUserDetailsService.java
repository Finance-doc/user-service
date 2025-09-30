package com.financedoc.user_service.auth.service;

import com.financedoc.user_service.auth.security.CustomUserDetails;
import com.financedoc.user_service.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService {
    private final UserRepository userRepository;

    public UserDetails loadUserByUserId(String userId) {
        // userId 타입에 맞춰 조회 (PK가 Long이면 parse, 문자열이면 그대로)
        return userRepository.findByUserId(userId) // 또는 findById(Long.parseLong(userId))
                .map(CustomUserDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userId));
    }
}
