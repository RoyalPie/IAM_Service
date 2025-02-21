package com.example.IAM_Service.jwt;

import com.example.IAM_Service.entity.ERole;
import com.example.IAM_Service.entity.Role;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.Set;

@Component
@Slf4j
public class JwtUtils {
    private final RSAKeyUtil rsaKeyUtil;
    @Value("${jwt.expiration}")
    private Long ACCESS_EXPIRY_DATE;

    @Value("${jwt.RefreshExpirationMs}")
    private Long REFRESH_EXPIRY_DATE;

    @Value("${jwt.ResetExpirationMs}")
    private Long RESET_EXPIRY_DATE;

    public JwtUtils(RSAKeyUtil rsaKeyUtil) {
        this.rsaKeyUtil = rsaKeyUtil;
    }

    public String generateToken(String email, Set<Role> roles) throws Exception {
        PrivateKey privateKey = rsaKeyUtil.getPrivateKey();
        Date now = new Date();
        List<String> roleNames = roles.stream().map(role -> role.getName().name()).toList();
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_EXPIRY_DATE))
                .claim("roles", roleNames)
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }
    public String generateRefreshToken(String email) throws Exception {
        PrivateKey privateKey = rsaKeyUtil.getPrivateKey();
        Date now = new Date();
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(new Date(System.currentTimeMillis() + RESET_EXPIRY_DATE))
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }
    public String generateResetToken(String email) throws Exception {
        PrivateKey privateKey = rsaKeyUtil.getPrivateKey();
        Date now = new Date();
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRY_DATE))
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }
    public List<String> extractRoles(String token) throws Exception {
        Claims claims = extractClaims(token);

        return claims.get("roles", List.class);
    }
    public Claims extractClaims(String token) throws Exception {
        PublicKey publicKey = rsaKeyUtil.getPublicKey();
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
    }
    public String extractEmail(String token) throws Exception {
        return extractClaims(token).getSubject();
    }
    public Date extractExpiration(String token) throws Exception {
        return extractClaims(token).getExpiration();
    }
    public boolean isTokenExpired(String token) throws Exception {
        return extractClaims(token).getExpiration().before(new Date());
    }
    public boolean validateToken(String token, String email) throws Exception {
        return (email.equals(extractEmail(token)) && !isTokenExpired(token));
    }
    public String extractTokenFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");

        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }

        return null;
    }
}
