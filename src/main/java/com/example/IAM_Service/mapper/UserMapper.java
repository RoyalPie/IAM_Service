package com.example.IAM_Service.mapper;

import com.example.IAM_Service.dto.UserDto;
import com.example.IAM_Service.entity.Role;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class UserMapper {
    @Value("${default.profilePicture}")
    private String defaultProfilePicture;

    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    // Convert DTO to Entity
    public User toEntity(UserDto dto) {
        User user = new User();
        user.setUsername(dto.getUsername());
        user.setEmail(dto.getEmail());
        user.setProfilePicturePath(defaultProfilePicture);
        user.setPhoneNumber(dto.getPhoneNumber());
        user.setAddress(dto.getAddress());
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setDateOfBirth(dto.getDateOfBirth());
        user.setYoE(dto.getYoE());
        user.setActive(dto.getIsActive() != null ? dto.getIsActive() : true);

        user.setPassword(passwordEncoder.encode("123456"));

        Set<Role> roles = new HashSet<>();

        Role defaultRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Error: Default role 'USER' is not found."));
        roles.add(defaultRole);

        return user;
    }

    public UserDto toDto(User user) {
        UserDto dto = new UserDto();
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setProfilePicturePath(user.getProfilePicturePath());
        dto.setPhoneNumber(user.getPhoneNumber());
        dto.setAddress(user.getAddress());
        dto.setFirstName(user.getFirstName());
        dto.setLastName(user.getLastName());
        dto.setDateOfBirth(user.getDateOfBirth());
        dto.setYoE(user.getYoE());
        dto.setIsActive(user.isActive());

        return dto;
    }
    public List<UserDto> toDtoList(List<User> users) {
        return users.stream().map(this::toDto).collect(Collectors.toList());
    }

    public List<User> toEntityList(List<UserDto> dtos) {
        return dtos.stream().map(this::toEntity).collect(Collectors.toList());
    }
}
