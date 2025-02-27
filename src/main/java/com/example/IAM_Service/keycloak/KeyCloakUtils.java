package com.example.IAM_Service.keycloak;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.Map;

public class KeyCloakUtils {
    private final JwtDecoder jwtDecoder;

    public KeyCloakUtils(String jwkSetUri) {
        this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    public Map<String, Object> decodeJwt(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getClaims();
        }
        return null;
    }
}
