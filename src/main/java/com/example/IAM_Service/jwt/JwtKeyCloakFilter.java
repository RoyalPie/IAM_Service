package com.example.IAM_Service.jwt;

import com.example.IAM_Service.service.JwtTokenBlackListService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
@Component
public class JwtKeyCloakFilter extends OncePerRequestFilter {
    private final KeycloakUtil keycloakUtil;

    private final JwtTokenBlackListService blackListService;

    Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    @Autowired
    public JwtKeyCloakFilter(KeycloakUtil keycloakUtil,
                             JwtTokenBlackListService blackListService) {
        this.keycloakUtil = keycloakUtil;
        this.blackListService = blackListService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            try {
                String email = keycloakUtil.extractUsernameFromToken(token);
                if (email != null && !blackListService.isBlacklisted(token)) {
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(email, null, Collections.emptyList());

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {
                logger.error("Invalid token or username", e);
            }
        }

        chain.doFilter(request, response);
    }

}
