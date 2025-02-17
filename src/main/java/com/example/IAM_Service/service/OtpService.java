package com.example.IAM_Service.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Service
public class OtpService {
    @Autowired
    EmailService emailService;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Value("${otp.expiration}")
    private Long expiration;

    public String generateAndSendOtp(String email) {
        if(redisTemplate.hasKey(email)){
            return "An OTP already been sent. Please check your email";
        }

        String otp = String.valueOf(new SecureRandom().nextInt(900000) + 100000); // 6-digit OTP
        redisTemplate.opsForValue().set(email, otp, expiration, TimeUnit.MILLISECONDS);
        emailService.sendOtpEmail(email, otp);
        return "OTP sent to your email. Please verify to proceed.";
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
