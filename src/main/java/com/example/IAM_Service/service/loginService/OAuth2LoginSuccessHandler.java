package com.example.IAM_Service.service.loginService;

import com.example.IAM_Service.entity.Role;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.payload.response.MessageResponse;
import com.example.IAM_Service.repository.RoleRepository;
import com.example.IAM_Service.repository.UserRepository;
import com.example.IAM_Service.service.KeycloakService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder encoder;
    private final KeycloakService keycloakService;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");

        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isEmpty()) {

            User newUser = new User();
            newUser.setEmail(oauth2User.getAttribute("email"));
            newUser.setPassword(encoder.encode("123456"));
            newUser.setFirstName(oauth2User.getAttribute("given_name"));
            newUser.setLastName(oauth2User.getAttribute("family_name"));
            newUser.setProfilePicturePath(oauth2User.getAttribute("picture"));
            newUser.setUsername(oauth2User.getAttribute("given_name").toString()+oauth2User.getAttribute("family_name").toString());
            Set<Role> roles = new HashSet<>();

            Role defaultRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new RuntimeException("Error: Default role 'USER' is not found."));
            roles.add(defaultRole);

            newUser.setRoles(roles);
            userRepository.save(newUser);
            try {
                String keycloakUserId = keycloakService.createUserInKeycloakFromGG(newUser);
                newUser.setKeycloakUserId(keycloakUserId);
                userRepository.save(newUser);
            } catch (Exception e) {
                throw new RuntimeException("Cant create Keycloak account");
            }
        }

        response.sendRedirect("/user/token?email="+email);
    }
}
