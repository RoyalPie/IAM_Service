package com.example.IAM_Service.jwt;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.stereotype.Component;

@Component
public class KeycloakUtil {
    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation("http://localhost:8080/realms/testing-realm");
    }
    public String extractUsernameFromToken(String token) {
        try {
            return jwtDecoder().decode(token).getClaim("email");
        } catch (Exception e) {
            throw new RuntimeException("Token is invalid or could not extract claim", e);
        }
    }
    public String extractTokenFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }

}
