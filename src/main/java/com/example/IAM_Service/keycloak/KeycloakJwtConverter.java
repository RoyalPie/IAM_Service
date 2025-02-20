package com.example.IAM_Service.keycloak;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.stream.Collectors;

@Component
public class KeycloakJwtConverter implements Converter<Jwt, UsernamePasswordAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public UsernamePasswordAuthenticationToken convert(Jwt jwt) {
        Collection<SimpleGrantedAuthority> authorities = authoritiesConverter.convert(jwt).stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthority()))
                .collect(Collectors.toSet());

        String username = jwt.getClaim("email");

        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }
}
