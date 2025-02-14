package com.example.IAM_Service.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
public class OtpService {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Value("${otp.expiration}")
    private Long expiration;

    public String generateOtp(String email) {
        String otp = String.valueOf(new Random().nextInt(900000) + 100000); // 6-digit OTP
        redisTemplate.opsForValue().set(email, otp, expiration, TimeUnit.MILLISECONDS);
        return otp;
    }
    @Transactional
    public boolean verifyOtp(String email, String enteredOtp) {
        if (!redisTemplate.hasKey(email)) {
            return false;
        }
        boolean isValid = Objects.equals(redisTemplate.opsForValue().get(email), enteredOtp);
        if (isValid) {
            redisTemplate.delete(email);
        }
        return isValid;
    }
}
