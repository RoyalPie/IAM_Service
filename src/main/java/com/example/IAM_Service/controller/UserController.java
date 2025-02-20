package com.example.IAM_Service.controller;

import com.example.IAM_Service.dto.UserDto;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.payload.request.ChangePasswordRequest;
import com.example.IAM_Service.payload.response.MessageResponse;
import com.example.IAM_Service.repository.UserRepository;
import com.example.IAM_Service.service.CloudinaryService;
import com.example.IAM_Service.service.UserActivityLogService;
import com.example.IAM_Service.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {
    private final UserService userService;
    private final CloudinaryService cloudinaryService;
    private final UserRepository userRepository;
    private final UserActivityLogService userActivityLogService;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/user-info")
    public ResponseEntity<UserDto> userinfo(@AuthenticationPrincipal String email) {
        return userService.findbyEmail(email)
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
    public String update(@AuthenticationPrincipal String email, @RequestBody @Valid UserDto user) {
        Long userId = userService.findbyEmail(email)
                .map(User::getId)
                .orElseThrow(()->new UsernameNotFoundException("User not found: " + email));
        return userService.updateUser(userId,user);
    }
    @PutMapping("/change-password")
    public ResponseEntity<?> updatepassword(@RequestBody @Valid ChangePasswordRequest request, @AuthenticationPrincipal String email, HttpServletRequest httpRequest) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        String ip = httpRequest.getRemoteAddr();
        String userAgent = httpRequest.getHeader("User-Agent");
        userActivityLogService.logActivity(user, "CHANGE_PASSWORD", ip, userAgent);
        return ResponseEntity.ok(new MessageResponse(userService.updatePassword(user.getId(), request)));
    }
    @PostMapping("/change-profile-image")
    public ResponseEntity<?> updateProfileImage(@RequestParam("image")MultipartFile file, @AuthenticationPrincipal String email){
        Map data = this.cloudinaryService.upload(file);
        String imageUrl = data.get("secure_url").toString();
        userService.updateProfileImage(email, imageUrl);
        return new ResponseEntity<>(userRepository.findByEmail(email).map(User::getProfilePicturePath), HttpStatus.OK);
    }
    @GetMapping("/token")
    public Map<String, Object> getTokens(Authentication authentication) {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                "keycloak", authentication.getName()
        );
        return Map.of(
                "access-token", client.getAccessToken().getTokenValue(),
                "refresh-token", client.getRefreshToken().getTokenValue()
        );
    }
}
