package com.example.IAM_Service.service.IService;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

public interface LogoutService {
    ResponseEntity<?> logout(HttpServletRequest request)throws Exception;
}
