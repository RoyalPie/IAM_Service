package com.example.IAM_Service.service.logoutService;

import com.example.IAM_Service.keycloak.KeyCloakUtils;
import com.example.IAM_Service.repository.UserRepository;
import com.example.IAM_Service.service.IService.LogoutService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service("keycloakLogoutService")
public class KeycloakLogoutService implements LogoutService {
    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;
    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;
    @Autowired
    private UserRepository userRepository;

    @Override
    public ResponseEntity<?> logout(HttpServletRequest request) {
        // Injected KeyCloakUtils (Avoid creating new instance on each request)
        KeyCloakUtils keyCloakUtils = new KeyCloakUtils("http://localhost:8080/realms/testing-realm/protocol/openid-connect/certs");
        Map<String, Object> claims = keyCloakUtils.decodeJwt(request);
        String id = claims.get("sub") != null ? (String) claims.get("sub") : "";

        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient("keycloak", id);

        String refreshToken = client.getRefreshToken().getTokenValue();

        // Prepare Keycloak logout request
        Map<String, String> requestBody = Map.of(
                "client_id", clientId,
                "client_secret", clientSecret,
                "refresh_token", refreshToken
        );

        HttpEntity<Map<String, String>> logoutRequest = new HttpEntity<>(requestBody, new HttpHeaders());
        ResponseEntity<String> response = new RestTemplate().postForEntity(
                "http://localhost:8080/realms/testing-realm/protocol/openid-connect/logout",
                logoutRequest,
                String.class
        );

        return response.getStatusCode().is2xxSuccessful()
                ? ResponseEntity.ok("User logged out successfully")
                : ResponseEntity.status(response.getStatusCode()).body("Logout failed");
    }
}
