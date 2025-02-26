package com.example.IAM_Service.controller;

import com.example.IAM_Service.entity.Permission;
import com.example.IAM_Service.entity.Role;
import com.example.IAM_Service.service.SystemAdminService;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin")
public class SystemAdminController {
    private final SystemAdminService adminService;

    public SystemAdminController(SystemAdminService adminService) {
        this.adminService = adminService;
    }

    @PreAuthorize("hasPermission(authentication, 'ROLE.VIEW')")
    @GetMapping("/view-roles")
    public ResponseEntity<Page<Role>> getAllRoles(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir) {
        return ResponseEntity.ok(adminService.getAllRoles(page, size, sortBy, sortDir));
    }

    @PreAuthorize("hasPermission(authentication, 'PERMISSION.VIEW')")
    @GetMapping("/view-permissions")
    public ResponseEntity<Page<Permission>> getAllPermissions(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir) {
        return ResponseEntity.ok(adminService.getAllPermissions(page, size, sortBy, sortDir));
    }

    @PreAuthorize("hasPermission(authentication, 'ROLE.CREATE')")
    @PostMapping("/create-role")
    public ResponseEntity<Role> createRole(@RequestBody Role role) {
        if(role.getName().isEmpty()) return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        String roleName ="ROLE_"+ role.getName().toUpperCase();
        role.setName(roleName);
        return ResponseEntity.ok(adminService.createRole(role));
    }

    @PreAuthorize("hasPermission(authentication, 'ROLE.DELETE')")
    @DeleteMapping("/delete-role")
    public ResponseEntity<String> deleteRole(@RequestParam String roleName) {
        adminService.deleteRole(roleName);
        return ResponseEntity.ok("Role deleted successfully");
    }

    @PreAuthorize("hasPermission(authentication, 'PERMISSION.CREATE')")
    @PostMapping("/create-permission")
    public ResponseEntity<String> createPermission(@RequestParam String resource, @RequestParam String action) {
        adminService.createPermission(resource, action);
        return ResponseEntity.ok("Permission created successfully");
    }

    @PreAuthorize("hasPermission(authentication, 'ROLE.UPDATE')")
    @PostMapping("/assign-permission")
    public ResponseEntity<String> assignPermission(@RequestParam String roleName, @RequestParam String permissionName) {
        adminService.addPermissionToRole(roleName, permissionName);
        return ResponseEntity.ok("Permission added to role successfully");
    }

    @PreAuthorize("hasPermission(authentication, 'ROLE.UPDATE')")
    @PostMapping("/remove-permission")
    public ResponseEntity<String> removePermission(@RequestParam String roleName, @RequestParam String permissionName) {
        adminService.removePermissionFromRole(roleName, permissionName);
        return ResponseEntity.ok("Permission removed from role successfully");
    }

    @PreAuthorize("hasPermission(authentication, 'PERMISSION.DELETE')")
    @DeleteMapping("/delete-permission")
    public ResponseEntity<String> deletePermission(@RequestParam String permissionName) {
        adminService.deletePermission(permissionName);
        return ResponseEntity.ok("Permission deleted successfully");
    }
}
