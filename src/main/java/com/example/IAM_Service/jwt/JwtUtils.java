package com.example.IAM_Service.jwt;

import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
@Component
@Slf4j
public class JwtUtils {
    private final RSAKeyUtil rsaKeyUtil;
    @Value("${jwt.expiration}")
    private Long EXPIRY_DATE;

    public JwtUtils(RSAKeyUtil rsaKeyUtil) {
        this.rsaKeyUtil = rsaKeyUtil;
    }

    public String generateToken(String username) throws Exception {
        PrivateKey privateKey = rsaKeyUtil.getPrivateKey();
        Date now = new Date();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRY_DATE))
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }
    public Claims extractClaims(String token) throws Exception {
        PublicKey publicKey = rsaKeyUtil.getPublicKey();
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
    }
    public String extractUsername(String token) throws Exception {
        return extractClaims(token).getSubject();
    }
    public Date extractExpiration(String token) throws Exception {
        return extractClaims(token).getExpiration();
    }
    public boolean isTokenExpired(String token) throws Exception {
        return extractClaims(token).getExpiration().before(new Date());
    }
    public boolean validateToken(String token, String username) throws Exception {
        return (username.equals(extractUsername(token)) && !isTokenExpired(token));
    }
    public String extractTokenFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");

        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }

        return null;
    }
}
