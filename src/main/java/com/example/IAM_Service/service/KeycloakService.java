package com.example.IAM_Service.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class KeycloakService {

    @Value("${keycloak.server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.realm}")
    private String keycloakRealm;

    @Value("${keycloak.user-creation.username}")
    private String keycloakUsername;

    @Value("${keycloak.user-creation.password}")
    private String keycloakPassword;

    @Value("${keycloak.enabled}")
    private boolean keycloakEnabled;

    private final RestTemplate restTemplate;

    public KeycloakService(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    public String createUserInKeycloak(String username, String email, String password) {
        if (!keycloakEnabled) {
            return null; // Nếu Keycloak bị tắt, bỏ qua việc tạo user
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(getAdminAccessToken());

        Map<String, Object> user = new HashMap<>();
        user.put("username", username);
        user.put("email", email);
        user.put("enabled", true);
        user.put("credentials", List.of(Map.of("type", "password", "value", password, "temporary", false)));

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(user, headers);

        ResponseEntity<Void> response = restTemplate.exchange(
                keycloakServerUrl + "/admin/realms/" + keycloakRealm + "/users",
                HttpMethod.POST, request, Void.class);

        if (response.getStatusCode() == HttpStatus.CREATED) {
            return getUserIdFromKeycloak(username);
        } else {
            throw new RuntimeException("Failed to create user in Keycloak");
        }
    }

    private String getAdminAccessToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", "admin-cli");
        form.add("grant_type", "password");
        form.add("username", keycloakUsername);
        form.add("password", keycloakPassword);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
                keycloakServerUrl + "/realms/master/protocol/openid-connect/token",
                request, Map.class);

        return response.getBody().get("access_token").toString();
    }

    private String getUserIdFromKeycloak(String username) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getAdminAccessToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<List> response = restTemplate.exchange(
                keycloakServerUrl + "/admin/realms/" + keycloakRealm + "/users?username=" + username,
                HttpMethod.GET, request, List.class);

        if (!response.getBody().isEmpty()) {
            Map<String, Object> user = (Map<String, Object>) response.getBody().get(0);
            return user.get("id").toString();
        }
        return null;
    }
}
