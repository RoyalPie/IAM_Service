package com.example.IAM_Service.service;

import com.example.IAM_Service.dto.UserDto;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    private final UserRepository repository;

    public UserService(UserRepository repository) {
        this.repository = repository;
    }

    public Optional<User> findbyUsername(String username){
        return repository.findByUsername(username);
    }

    public String updateUser(Long id, @Valid UserDto user){
        User existingUser = repository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User with ID " + id + " not found!"));
        if (user.getUsername() != null && !user.getUsername().isEmpty()) {
            existingUser.setUsername(user.getUsername());
        }
        if (user.getAddress() != null && !user.getAddress().isEmpty()) {
            existingUser.setAddress(user.getAddress());
        }
        if (user.getRoles() != null && !user.getRoles().isEmpty()) {
            existingUser.setRoles(user.getRoles());
        }
        if (user.getEmail() != null && !user.getEmail().isEmpty()) {
            existingUser.setEmail(user.getEmail());
        }
        if (user.getFirstName() != null && !user.getFirstName().isEmpty()) {
            existingUser.setFirstName(user.getFirstName());
        }
        if (user.getLastName() != null && !user.getLastName().isEmpty()) {
            existingUser.setLastName(user.getLastName());
        }
        if (user.getProfilePicturePath() != null && !user.getProfilePicturePath().isEmpty()) {
            existingUser.setProfilePicturePath(user.getProfilePicturePath());
        }
        if (user.getPhoneNumber() != null && !user.getPhoneNumber().isEmpty()) {
            existingUser.setPhoneNumber(user.getPhoneNumber());
        }
        if (user.getDateOfBirth() != null) {
            existingUser.setDateOfBirth(user.getDateOfBirth());
        }
        repository.save(existingUser);
        return "Cập nhật user thành công";
    }
}
