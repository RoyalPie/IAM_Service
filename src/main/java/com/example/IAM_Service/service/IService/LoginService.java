package com.example.IAM_Service.service.IService;

import com.example.IAM_Service.payload.request.LoginRequest;
import org.springframework.http.ResponseEntity;

public interface LoginService {
    ResponseEntity<?> authenticate(LoginRequest loginRequest);
}
