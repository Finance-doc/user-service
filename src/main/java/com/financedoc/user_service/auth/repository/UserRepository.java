package com.financedoc.user_service.auth.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.financedoc.user_service.auth.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByKakaoId(Long kakaoId);
    Optional<Long>findRecentTributeCountById(Long userId);
    Optional<User> findByUserId(String userId);
}

