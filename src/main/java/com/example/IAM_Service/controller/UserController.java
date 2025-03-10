package com.example.IAM_Service.controller;

import com.example.IAM_Service.dto.RoleDto;
import com.example.IAM_Service.dto.UserDto;
import com.example.IAM_Service.entity.RefreshToken;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.jwt.JwtUtils;
import com.example.IAM_Service.payload.request.ChangePasswordRequest;
import com.example.IAM_Service.payload.response.MessageResponse;
import com.example.IAM_Service.repository.UserRepository;
import com.example.IAM_Service.service.CloudinaryService;
import com.example.IAM_Service.service.StorageService;
import com.example.IAM_Service.service.UserActivityLogService;
import com.example.IAM_Service.service.UserService;
import com.example.IAM_Service.service.refreshTokenService.RefreshTokenService;
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

import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {
    private final UserService userService;
    private final CloudinaryService cloudinaryService;
    private final UserRepository userRepository;
    private final UserActivityLogService userActivityLogService;
    private final RefreshTokenService refreshTokenService;
    private final StorageService storageService;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/user-info")
    public ResponseEntity<UserDto> userinfo(@AuthenticationPrincipal String email, Authentication authentication) {
        return userService.findbyEmail(email)
                .map(user -> {
                    UserDto userDto = UserDto.builder()
                            .username(user.getUsername())
                            .email(user.getEmail())
                            .roles(user.getRoles()
                                    .stream()
                                    .map(role -> new RoleDto(role.getName()))
                                    .collect(Collectors.toSet())
                            )
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
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        return userService.updateUser(userId, user);
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
    public ResponseEntity<?> updateProfileImage(@RequestParam("image") MultipartFile[] file, @AuthenticationPrincipal String email) throws IOException {
        Map data = this.storageService.uploadFile(file, email);
        String imageUrl = data.get("url").toString();
        userService.updateProfileImage(email, imageUrl);
        return new ResponseEntity<>(userRepository.findByEmail(email).map(User::getProfilePicturePath), HttpStatus.OK);
    }

    @PostMapping("/upload-file")
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile[] file, @AuthenticationPrincipal String email) throws IOException {
        Map data = this.storageService.uploadFile(file, email);

        return ResponseEntity.ok("");
    }

    @GetMapping("/token")
    public Map<String, Object> getTokens(Authentication authentication, @RequestParam(required = false) String email) throws Exception {
        if(email == null){
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                    "keycloak", authentication.getName()
            );
            return Map.of(
                    "access-token", client.getAccessToken().getTokenValue(),
                    "refresh-token", client.getRefreshToken().getTokenValue()
            );
        }else {
            String jwt = jwtUtils.generateToken(email);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(email);

            return Map.of(
                    "access-token", jwt,
                    "refresh-token", refreshToken.getToken(),
                    "email", email
            );
        }
    }
}
