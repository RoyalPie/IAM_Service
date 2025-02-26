package com.example.IAM_Service.service;

import com.example.IAM_Service.repository.PermissionRepository;
import com.example.IAM_Service.repository.RoleRepository;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import java.io.Serializable;
import java.util.Set;

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
        if (authentication == null || targetDomainObject == null || permission == null) {
            return false;
        }
        String email = authentication.getName();

        if(roleRepository.isRoot(email)) return true;

        Set<String> userPermissions = permissionRepository.findUserPermissions(email);
        return userPermissions.contains(permission.toString());
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null || targetId == null || targetType == null || permission == null) {
            return false;
        }

        String email = authentication.getName();

        if(roleRepository.isRoot(email)) return true;

        Set<String> userPermissions = permissionRepository.findUserPermissions(email);
        return userPermissions.contains(permission.toString());
    }
}
