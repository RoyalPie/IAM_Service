package com.example.IAM_Service.service;

import com.example.IAM_Service.entity.Permission;
import com.example.IAM_Service.jwt.CustomAuthenticationToken;
import com.example.IAM_Service.repository.PermissionRepository;
import com.example.IAM_Service.repository.RoleRepository;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;

    public CustomPermissionEvaluator(PermissionRepository permissionRepository, RoleRepository roleRepository) {
        this.permissionRepository = permissionRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {

        CustomAuthenticationToken authToken = (CustomAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        if (authToken.getIsRoot()) return true;

        Set<String> userPermissions = authToken.getPermissions().stream()
                .map(p -> p.getResource() + "." + p.getPermission())
                .collect(Collectors.toSet());

        return userPermissions.contains(permission.toString());
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null || targetId == null || targetType == null || permission == null) {
            return false;
        }

        String email = authentication.getName();

        if (roleRepository.isRoot(email)) return true;

        Set<String> userPermissions = permissionRepository.findUserPermissions(email);
        return userPermissions.contains(permission.toString());
    }
}
