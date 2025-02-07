package com.example.IAM_Service.jwt;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
@Component
@Slf4j
public class JwtUtils {
    @Value("${jwt.secret}")
    private String JWT_SECRET;

    @Value("${jwt.expiration}")
    private Long EXPIRY_DATE;

    public String generateToken(String username) {
        Date now = new Date();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRY_DATE))
                .signWith(SignatureAlgorithm.HS512, JWT_SECRET)
                .compact();
    }
    public Claims extractClaims(String token) {
        return Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token).getBody();
    }
    public String getUserNameFromJWT(String token) {
        return extractClaims(token).getSubject();
    }
    public boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }
    public boolean validateToken(String token, String username) {
        return (username.equals(getUserNameFromJWT(token)) && !isTokenExpired(token));
    }
}
