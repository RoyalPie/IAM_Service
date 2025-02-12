package com.example.IAM_Service.controller;

import com.example.IAM_Service.dto.UserDto;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.payload.request.ChangePasswordRequest;
import com.example.IAM_Service.payload.response.MessageResponse;
import com.example.IAM_Service.repository.UserRepository;
import com.example.IAM_Service.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {
    private final UserService userService;

    @Autowired
    UserRepository userRepository;

    @GetMapping("/userinfo")
    public ResponseEntity<UserDto> userinfo(@AuthenticationPrincipal String username) {
        return userService.findbyUsername(username)
                .map(user -> {
                    UserDto userDto = UserDto.builder()
                            .username(user.getUsername())
                            .email(user.getEmail())
                            .roles(user.getRoles())
                            .profilePicturePath(user.getProfilePicturePath())
                            .phoneNumber(user.getPhoneNumber())
                            .address(user.getAddress())
                            .firstName(user.getFirstName())
                            .lastName(user.getLastName())
                            .dateOfBirth(user.getDateOfBirth())
                            .build();
                    return ResponseEntity.ok(userDto);
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body(null));
    }

    @PutMapping("/update")
    public String update(@AuthenticationPrincipal String username, @RequestBody @Valid UserDto user) {
        Long userId = userService.findbyUsername(username)
                .map(User::getId)
                .orElseThrow(()->new UsernameNotFoundException("User not found: " + username));
        return userService.updateUser(userId,user);
    }
    @PutMapping("/changepassword")
    public ResponseEntity<?> updatepassword(@RequestBody @Valid ChangePasswordRequest request, @AuthenticationPrincipal String username) {
        Long userId = userRepository.findByUsername(username)
                .map(User::getId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return ResponseEntity.ok(new MessageResponse(userService.updatePassword(userId, request)));
    }

}
