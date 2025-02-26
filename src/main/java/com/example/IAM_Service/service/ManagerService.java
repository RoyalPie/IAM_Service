package com.example.IAM_Service.service;

import com.example.IAM_Service.dto.RoleDto;
import com.example.IAM_Service.dto.UserDto;
import com.example.IAM_Service.entity.EmailDetails;
import com.example.IAM_Service.entity.RestrictedRole;
import com.example.IAM_Service.entity.Role;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.repository.RoleRepository;
import com.example.IAM_Service.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
public class ManagerService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private KeycloakService keycloakService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private RoleRepository roleRepository;

    public Page<UserDto> getAllUsers(int page, int size, String sortBy, String sortDir, String keyword) {
        Sort sort = sortDir.equalsIgnoreCase("desc") ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();
        Pageable pageable = PageRequest.of(page, size, sort);
        Page<User> users = userRepository.usersList(keyword, pageable);

        return users.map(user -> UserDto.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(user.getRoles()
                        .stream()
                        .map(role -> new RoleDto(role.getName()))
                        .collect(Collectors.toSet()))
                .address(user.getAddress())
                .phoneNumber(user.getPhoneNumber())
                .profilePicturePath(user.getProfilePicturePath())
                .dateOfBirth(user.getDateOfBirth())
                .isActive(user.isActive())
                .build()
        );
    }

    public String softDelete(String email){
        User existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User with Email " + email + " not found!"));
        existingUser.setDeleted(true);
        userRepository.save(existingUser);

        keycloakService.changeUserStatus(existingUser.getKeycloakUserId(), false);

        EmailDetails mail = new EmailDetails(existingUser.getEmail(), "Your account have been deleted!!!\n\nIf this is not your action or you want to report please contact us.","Account Deletion");
        emailService.sendSimpleMail(mail);
        return "Successful deleted user";
    }
    public String changeUserStatus(String email, Boolean status){
        User existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User with Email " + email + " not found or has been deleted!"));
        existingUser.setActive(status);
        userRepository.save(existingUser);

        keycloakService.changeUserStatus(existingUser.getKeycloakUserId(), status);

        EmailDetails mail = new EmailDetails(existingUser.getEmail(), "Your account have been deleted!!!\n\nIf this is not your action or you want to report please contact us.","Account Deletion");
        emailService.sendSimpleMail(mail);
        return status ? "Successful unlock user" : "Successful lock user";
    }
    public void assignRoleToUser(String email, String roleName) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found"));
        if (user.getRoles().contains(role)) {
            throw new RuntimeException("User already has this role");
        }
        if (RestrictedRole.isRestricted(roleName)) {
            throw new RuntimeException("You cannot assign this role: " + roleName);
        }
        user.getRoles().add(role);
        userRepository.save(user);
    }
    public void removeRoleFromUser(String email, String roleName) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found"));
        user.getRoles().remove(role);
        userRepository.save(user);
    }
}
