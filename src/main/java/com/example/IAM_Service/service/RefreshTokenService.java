package com.example.IAM_Service.service;

import com.example.IAM_Service.entity.RefreshToken;
import com.example.IAM_Service.repository.RefreshTokenRepository;
import com.example.IAM_Service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    @Value("${jwt.RefreshExpirationMs}")
    private Long refreshTokenDurationMs;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(Long userId) {
        deleteByUser(userId);
        refreshTokenRepository.flush();

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setUser(userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found")));
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());
        System.out.println("==========================="+ refreshToken);
        refreshToken = refreshTokenRepository.save(refreshToken);

        return refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new IllegalStateException("Refresh token was expired. Please make a new signin request");
        }

        return token;
    }

    @Transactional
    public void deleteByUser(Long userId) {
        refreshTokenRepository.deleteByUser(userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found")));
    }

}