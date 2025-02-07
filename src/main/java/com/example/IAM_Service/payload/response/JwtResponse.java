package com.example.IAM_Service.payload.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private String refreshToken;
    private String username;

    public JwtResponse(String accessToken, String refreshToken, String username) {
        this.token = accessToken;
        this.refreshToken = refreshToken;
        this.username = username;
    }
}