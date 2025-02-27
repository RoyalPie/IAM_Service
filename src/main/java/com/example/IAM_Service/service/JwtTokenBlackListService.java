package com.example.IAM_Service.service;

import com.example.IAM_Service.jwt.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class JwtTokenBlackListService {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private JwtUtils jwtUtils;

    public void addToBlacklist(HttpServletRequest request) throws Exception {
        String token = jwtUtils.extractTokenFromRequest(request);
        Date expiry = jwtUtils.extractExpiration(token);

        long expiration = expiry.getTime() - System.currentTimeMillis();
        redisTemplate.opsForValue().set(token, "blacklisted", expiration, TimeUnit.MILLISECONDS);
    }

    public Boolean isBlacklisted(String token) {
        return redisTemplate.hasKey(token);
    }
}
