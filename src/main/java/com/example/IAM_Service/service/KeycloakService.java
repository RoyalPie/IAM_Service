package com.example.IAM_Service.service;

import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.payload.request.SignupRequest;
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
import java.util.Optional;

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

    public String createUserInKeycloak(SignupRequest signupRequest) {

        Map<String, Object> user = Map.of(
                "username", signupRequest.getUsername(),
                "email", signupRequest.getEmail(),
                "enabled", true,
                "firstName", signupRequest.getFirstName(),
                "lastName", signupRequest.getLastName(),
                "credentials", List.of(Map.of(
                        "type", "password",
                        "value", signupRequest.getPassword(),
                        "temporary", false))
        );

        ResponseEntity<Void> response = sendAdminRequest(HttpMethod.POST, "/users", user, Void.class);

        if (response.getStatusCode() == HttpStatus.CREATED) {
            return getUserIdFromKeycloak(signupRequest.getUsername());
        } else {
            throw new RuntimeException("Failed to create user in Keycloak");
        }
    }
    public String createUserInKeycloakFromGG(User user) {

        Map<String, Object> keycloakUser = Map.of(
                "username", user.getUsername(),
                "email", user.getEmail(),
                "enabled", true,
                "firstName", user.getFirstName(),
                "lastName", user.getLastName(),
                "credentials", List.of(Map.of(
                        "type", "password",
                        "value", user.getPassword(),
                        "temporary", false))
        );

        ResponseEntity<Void> response = sendAdminRequest(HttpMethod.POST, "/users", keycloakUser, Void.class);

        if (response.getStatusCode() == HttpStatus.CREATED) {
            return getUserIdFromKeycloak(user.getUsername());
        } else {
            throw new RuntimeException("Failed to create user in Keycloak");
        }
    }

    public void changeUserStatus(String userId, Boolean status) {
        sendAdminRequest(HttpMethod.PUT, "/users/" + userId, Map.of("enabled", status), Void.class);
    }

    public void changeUserPassword(String userId, String newPassword) {
        sendAdminRequest(HttpMethod.PUT, "/users/" + userId + "/reset-password",
                Map.of("type", "password", "value", newPassword, "temporary", false), Void.class);
    }

    private <T> ResponseEntity<T> sendAdminRequest(HttpMethod method, String path, Map<String, Object> body, Class<T> responseType) {
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, getAuthHeaders());
        return restTemplate.exchange(keycloakServerUrl + "/admin/realms/" + keycloakRealm + path, method, request, responseType);
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

        return Optional.ofNullable(response.getBody())
                .map(body -> body.get("access_token"))
                .map(Object::toString)
                .orElseThrow(() -> new RuntimeException("Failed to obtain access token from Keycloak"));
    }

    private String getUserIdFromKeycloak(String username) {
        HttpEntity<Void> request = new HttpEntity<>(getAuthHeaders());

        ResponseEntity<List> response = restTemplate.exchange(
                keycloakServerUrl + "/admin/realms/" + keycloakRealm + "/users?username=" + username,
                HttpMethod.GET, request, List.class);

        return Optional.ofNullable(response.getBody())
                .filter(users -> !users.isEmpty())
                .map(users -> (Map<String, Object>) users.get(0))
                .map(user -> user.get("id").toString())
                .orElseThrow(() -> new RuntimeException("User not found in Keycloak"));
    }

    private HttpHeaders getAuthHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(getAdminAccessToken());
        return headers;
    }
}
