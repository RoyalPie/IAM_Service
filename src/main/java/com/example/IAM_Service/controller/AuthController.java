package com.example.IAM_Service.controller;

import com.example.IAM_Service.entity.*;
import com.example.IAM_Service.jwt.JwtUtils;
import com.example.IAM_Service.payload.request.*;
import com.example.IAM_Service.payload.response.JwtResponse;
import com.example.IAM_Service.payload.response.MessageResponse;
import com.example.IAM_Service.repository.RoleRepository;
import com.example.IAM_Service.repository.UserRepository;
import com.example.IAM_Service.service.*;
import com.example.IAM_Service.service.IService.LoginService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final LoginService loginService;

    @Autowired
    CloudinaryService cloudinaryService;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    UserService userService;

    @Autowired
    BCryptPasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    private JwtTokenBlackListService blackListService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private OtpService otpService;

    @Autowired
    private UserActivityLogService userActivityLogService;

    @Value("${default.profilePicture}")
    private String defaultProfilePicture;

    @PostMapping("/sign-in")
    public ResponseEntity<?> signIn(@Valid @RequestBody LoginRequest loginRequest) {
        return loginService.authenticate(loginRequest);
    }

    @PostMapping("/sign-in/verify-otp")
    public ResponseEntity<?> authenticateUser(@RequestBody OtpRequest otpRequest,HttpServletRequest request) {
        String otp = otpRequest.getOtp();
        String email = otpRequest.getEmail();
        try {
            if (otpService.verifyOtp(email, otp)) {
                String jwt = jwtUtils.generateToken(email);
                RefreshToken refreshToken = refreshTokenService.createRefreshToken(email);
                String ip = request.getRemoteAddr();
                String userAgent = request.getHeader("User-Agent");
                userActivityLogService.logActivity(userService.findbyEmail(email).orElseThrow(()-> new UsernameNotFoundException("Not found user with this email")), "LOGIN", ip, userAgent);

                return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(), email));
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid OTP code");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred while verifying OTP: " + e.getMessage());
        }
    }

    @PostMapping("/sign-up")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                if (role.equals("admin")) {
                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(adminRole);
                } else {
                    Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        user.setAddress(signUpRequest.getAddress());
        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());
        user.setDateOfBirth(signUpRequest.getDateOfBirth());
        user.setPhoneNumber(signUpRequest.getPhoneNumber());

        user.setProfilePicturePath(defaultProfilePicture);
        userRepository.save(user);
        EmailDetails email = new EmailDetails(user.getEmail(), "Welcome new User"+user.getUsername(),"Successful Registration");
        emailService.sendSimpleMail(email);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody RefreshTokenRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = null;
                    try {
                        token = jwtUtils.generateToken(user.getEmail());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    return ResponseEntity.ok(new MessageResponse("New JWT Token: "+token));
                })
                .orElseThrow(() -> new IllegalArgumentException("Refresh token is not in database!"));
    }

    @PostMapping("/sign-out")
    public ResponseEntity<?> logoutUser(HttpServletRequest request) throws Exception {
        String email = jwtUtils.extractEmail(jwtUtils.extractTokenFromRequest(request));
        User user = userRepository.findByEmail(email).orElseThrow(()->new UsernameNotFoundException("User not found: " + email));
        refreshTokenService.deleteByUser(user.getEmail());
        blackListService.addToBlacklist(request);
        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        userActivityLogService.logActivity(user, "LOGOUT", ip, userAgent);
        return ResponseEntity.ok(new MessageResponse("Logout successfully"));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotpassword(@RequestBody EmailDetails details){
        String resetToken = null;
        try {
            resetToken = jwtUtils.generateResetToken(details.getRecipient());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        details.setMsgBody("\nPlease click the link below to reset your password\n\nhttp://localhost:8080/api/auth/verify-reset-token?"+"email="+details.getRecipient()+"&token="+resetToken);
        details.setSubject("Change Password Mail");
        return ResponseEntity.ok(emailService.sendSimpleMail(details));
    }

    @GetMapping("/verify-reset-token")
    public ResponseEntity<String> verifyResetToken(@RequestParam String token) {

        if (token.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Reset token not found");
        }

        try {
            String email = jwtUtils.extractEmail(token);
            if (jwtUtils.validateToken(token, email) && !jwtUtils.isTokenExpired(token)) {
                return ResponseEntity.ok("Directed to change password page");
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid reset token");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
