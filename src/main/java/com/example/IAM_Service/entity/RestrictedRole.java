package com.example.IAM_Service.entity;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public enum RestrictedRole {
    ROLE_SUPER_ADMIN,
    ROLE_SYSTEM_ADMIN,
    ROLE_USER_MANAGER,
    ROLE_OWNER;

    private static final Set<String> RESTRICTED_ROLES =
            Arrays.stream(values()).map(Enum::name).collect(Collectors.toSet());

    public static boolean isRestricted(String roleName) {
        return RESTRICTED_ROLES.contains(roleName);
    }
}
