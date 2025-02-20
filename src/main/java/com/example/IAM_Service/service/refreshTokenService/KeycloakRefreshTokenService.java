package com.example.IAM_Service.service.refreshTokenService;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.*;

@Service
public class KeycloakRefreshTokenService {
    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    public String refreshToken(String refreshToken) {
        RestTemplate restTemplate = new RestTemplate();
        String KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/testing-realm/protocol/openid-connect/token";

        // Correctly encode parameters as a URL-encoded string
        String requestBody = "grant_type=refresh_token" +
                "&client_id=" + clientId +
                "&client_secret=" + clientSecret +
                "&refresh_token=" + refreshToken;

        // Set headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, headers);

        // Send request
        ResponseEntity<Map> response = restTemplate.exchange(
                KEYCLOAK_TOKEN_URL,
                HttpMethod.POST,
                requestEntity,
                Map.class
        );

        if (response.getStatusCode().is2xxSuccessful()) {
            Map<String, Object> responseBody = response.getBody();
            assert responseBody != null;
            return (String) responseBody.get("access_token");
        } else {
            throw new RuntimeException("Failed to refresh token: " + response.getStatusCode());
        }
    }
}

