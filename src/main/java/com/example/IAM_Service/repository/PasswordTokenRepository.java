package com.example.IAM_Service.repository;

import com.example.IAM_Service.entity.PasswordResetToken;
import com.example.IAM_Service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface PasswordTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);

    Boolean existsByUser(User user);

    @Modifying
    @Transactional
    int deleteByUser(User user);
}
