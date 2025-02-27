package com.example.IAM_Service.controller;

import com.example.IAM_Service.dto.UserDto;
import com.example.IAM_Service.payload.response.MessageResponse;
import com.example.IAM_Service.service.ManagerService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user-manager")
public class ManagerController {
    private final ManagerService managerService;

    public ManagerController(ManagerService managerService) {
        this.managerService = managerService;
    }

    @PreAuthorize("hasPermission(null, 'USER.VIEW')")
    @GetMapping("/users_list")
    public ResponseEntity<Page<UserDto>> getUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir,
            @RequestParam(defaultValue = "") String keyword) {

        Page<UserDto> users = managerService.getAllUsers(page, size, sortBy, sortDir, keyword);

        return ResponseEntity.ok(users);
    }

    @PreAuthorize("hasPermission(null, 'USER.DELETE')")
    @PutMapping("/delete")
    public ResponseEntity<?> softDeleteUser(@RequestParam String email) {
        return ResponseEntity.ok(new MessageResponse(managerService.softDelete(email)));
    }

    @PreAuthorize("hasPermission(null, 'USER.UPDATE')")
    @PutMapping("/status")
    public ResponseEntity<?> changeUserStatus(@RequestParam String email, Boolean status) {
        return ResponseEntity.ok(new MessageResponse(managerService.changeUserStatus(email, status)));
    }

    @PreAuthorize("hasPermission(null, 'USER.UPDATE')")
    @PostMapping("/assign-role")
    public ResponseEntity<String> assignRole(@RequestParam String email, @RequestParam String roleName) {
        managerService.assignRoleToUser(email, roleName);
        return ResponseEntity.ok("Role assigned successfully");
    }

    @PreAuthorize("hasPermission(null, 'USER.UPDATE')")
    @PostMapping("/remove-role")
    public ResponseEntity<String> removeRole(@RequestParam String email, @RequestParam String roleName) {
        managerService.removeRoleFromUser(email, roleName);
        return ResponseEntity.ok("Role removed successfully");
    }
}
