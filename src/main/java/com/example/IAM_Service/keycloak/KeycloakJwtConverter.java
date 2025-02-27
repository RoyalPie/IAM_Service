package com.example.IAM_Service.keycloak;

import com.example.IAM_Service.entity.Permission;
import com.example.IAM_Service.entity.Role;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.jwt.CustomAuthenticationToken;
import com.example.IAM_Service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class KeycloakJwtConverter implements Converter<Jwt, CustomAuthenticationToken> {
    @Autowired
    private UserRepository userRepository;

    private final JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public CustomAuthenticationToken convert(Jwt jwt) {
        String email = jwt.getClaim("email");

        User authenticatedUser = userRepository.findByEmailWithRolesAndPermissions(email)
                .orElseThrow(() -> new UsernameNotFoundException("Not found User with that email"));

        Set<Role> roles = authenticatedUser.getRoles();
        Set<Permission> permissions = roles.stream()
                .flatMap(role -> role.getPermissions().stream())
                .collect(Collectors.toSet());
        Boolean isRoot = roles.stream().anyMatch(Role::getIsRoot);

        return CustomAuthenticationToken.authenticated(email, null, null, roles, permissions, isRoot);
    }

}
