package com.example.IAM_Service.service.refreshTokenService;

import com.example.IAM_Service.entity.RefreshToken;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.jwt.JwtUtils;
import com.example.IAM_Service.repository.RefreshTokenRepository;
import com.example.IAM_Service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class RefreshTokenService {
    @Value("${jwt.RefreshExpirationMs}")
    private Long refreshTokenDurationMs;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtils jwtUtils;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(String email) throws Exception {
        User user = userRepository.findByEmail(email).orElseThrow(()->new RuntimeException("User not found"));
        RefreshToken refreshToken = new RefreshToken();
        if(refreshTokenRepository.existsByUser(user)){
            refreshToken = refreshTokenRepository.findByUser(user);
        }

        refreshToken.setUser(user);
        refreshToken.setToken(jwtUtils.generateRefreshToken(email));
        refreshToken = refreshTokenRepository.save(refreshToken);

        return refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        try {
            if (jwtUtils.isTokenExpired(token.getToken())) {
                refreshTokenRepository.delete(token);
                throw new IllegalStateException("Refresh token was expired. Please make a new sign-in request");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return token;
    }

    @Transactional
    public void deleteByUser(String email) {
        refreshTokenRepository.deleteByUser(userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found")));
    }
}