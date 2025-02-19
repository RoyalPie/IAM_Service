package com.example.IAM_Service.config;

import com.example.IAM_Service.service.IService.LoginService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoginServiceConfig {
    @Bean
    public LoginService loginService(
            @Value("${keycloak.enabled}") boolean keycloakEnabled,
            @Qualifier("customLoginService") LoginService customLoginService,
            @Qualifier("keycloakLoginService") LoginService keycloakLoginService) {
        return keycloakEnabled ? keycloakLoginService : customLoginService;
    }
}
