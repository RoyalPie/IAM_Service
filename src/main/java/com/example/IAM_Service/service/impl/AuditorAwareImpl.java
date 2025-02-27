package com.example.IAM_Service.service.impl;

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class AuditorAwareImpl implements AuditorAware<String> {

    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if ("anonymousUser".equals(authentication.getPrincipal()) || !authentication.isAuthenticated()) {
            return Optional.of("System");
        }

        return Optional.of(authentication.getName());
    }
}
