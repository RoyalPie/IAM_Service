package com.example.IAM_Service.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.IAM_Service.service.JwtTokenBlackListService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private JwtTokenBlackListService blackListService;

    Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            if (isKeycloakToken(token)) {
                chain.doFilter(request, response);
                return;
            }

            try {
                String email = jwtUtils.extractEmail(token);
                List<String> roles = jwtUtils.extractRoles(token);
                if (email != null && jwtUtils.validateToken(token, email) && !blackListService.isBlacklisted(token)) {
                    List<GrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(email, null, authorities);

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {

                logger.error("Invalid token or username", e);
            }
        }

        chain.doFilter(request, response);
    }
    private boolean isKeycloakToken(String token) {
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            return "http://localhost:8080/realms/testing-realm".equals(decodedJWT.getIssuer());
        } catch (Exception e) {
            return false;
        }
    }

}