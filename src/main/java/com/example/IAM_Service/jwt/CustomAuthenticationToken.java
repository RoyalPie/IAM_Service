package com.example.IAM_Service.jwt;

import com.example.IAM_Service.entity.Permission;
import com.example.IAM_Service.entity.Role;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import java.util.Collection;
import java.util.Set;

@Getter
public class CustomAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 1L;

    private final Object principal;
    private Object credentials;
    private final Set<Role> roles;
    private final Set<Permission> permissions;
    private final Boolean isRoot;

    // Constructor for Unauthenticated Token (Login Request)
    public CustomAuthenticationToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        this.roles = null;
        this.permissions = null;
        this.isRoot = false;
        setAuthenticated(false);
    }

    // Constructor for Authenticated Token (After Verification)
    public CustomAuthenticationToken(Object principal, Object credentials,
                                     Collection<? extends GrantedAuthority> authorities,
                                     Set<Role> roles, Set<Permission> permissions, Boolean isRoot) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.roles = roles;
        this.permissions = permissions;
        this.isRoot = isRoot;
        super.setAuthenticated(true);
    }

    // Factory method for creating an unauthenticated token
    public static CustomAuthenticationToken unauthenticated(Object principal, Object credentials) {
        return new CustomAuthenticationToken(principal, credentials);
    }

    // Factory method for creating an authenticated token
    public static CustomAuthenticationToken authenticated(Object principal, Object credentials,
                                                          Collection<? extends GrantedAuthority> authorities,
                                                          Set<Role> roles, Set<Permission> permissions, Boolean isRoot) {
        return new CustomAuthenticationToken(principal, credentials, authorities, roles, permissions, isRoot);
    }

    public Boolean isRoot() {
        return isRoot;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }


    // Override setAuthenticated to prevent external changes
    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted manually - use the authenticated constructor.");
        }
        super.setAuthenticated(false);
    }

    // Erase credentials for security
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}
