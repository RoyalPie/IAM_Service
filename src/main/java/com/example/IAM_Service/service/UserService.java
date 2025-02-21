package com.example.IAM_Service.service;

import com.example.IAM_Service.dto.UserDto;
import com.example.IAM_Service.entity.EmailDetails;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.jwt.JwtUtils;
import com.example.IAM_Service.payload.request.ChangePasswordRequest;
import com.example.IAM_Service.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    BCryptPasswordEncoder encoder;

    @Autowired
    private EmailService emailService;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private KeycloakService keycloakService;

    public Optional<User> findbyEmail(String username) {
        return userRepository.findByEmail(username);
    }

    public String updateUser(Long id, @Valid UserDto user) {
        User existingUser = userRepository.findById(id)
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
        userRepository.save(existingUser);
        EmailDetails email = new EmailDetails(existingUser.getEmail(), "Your Information have been changed!!!\n\nIf this is not your action please contact us.","Successful Changed Information");
        emailService.sendSimpleMail(email);
        return "Cập nhật user thành công";
    }

    public String updatePassword(Long id, ChangePasswordRequest request) {
        User existingUser = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User with ID " + id + " not found!"));

        if (!encoder.matches(request.getOldPassword(), existingUser.getPassword())) {
            return "Sai mật khẩu!! Vui lòng nhập lại";
        }
        if (request.getNewPassword() != null && !request.getNewPassword().isEmpty()) {
            existingUser.setPassword(encoder.encode(request.getNewPassword()));
        }
        keycloakService.changeUserPassword(existingUser.getKeycloakUserId(), request.getNewPassword());
        userRepository.save(existingUser);
        EmailDetails mail = new EmailDetails(existingUser.getEmail(), "Your password have been changed!!!\n\nIf this is not your action please contact us.","Successful Changed Password");
        emailService.sendSimpleMail(mail);
        return "Đổi mật khẩu thành công";
    }
    public String updateProfileImage(String email, String imageUrl) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User with Email " + email + " not found!"));

        if (imageUrl != null && !imageUrl.isEmpty()) {
            user.setProfilePicturePath(imageUrl);
        }

        userRepository.save(user);
        return "Đổi ảnh đại diện thành công";
    }
    public String forgotPassword(String email, String newpassword) {
        User existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User with Email " + email + " not found!"));
        if (newpassword != null && !newpassword.isEmpty()) {
            existingUser.setPassword(encoder.encode(newpassword));
        }
        userRepository.save(existingUser);
        EmailDetails mail = new EmailDetails(existingUser.getEmail(), "Your password have been changed!!!\n\nIf this is not your action please contact us.","Successful Changed Password");
        emailService.sendSimpleMail(mail);
        return "Đổi mật khẩu thành công";
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
    public String restoreUser(String email){
        User existingUser = userRepository.findByDeletedEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User with Email " + email + " not found or not deleted!"));
        existingUser.setDeleted(false);
        userRepository.save(existingUser);

        keycloakService.changeUserStatus(existingUser.getKeycloakUserId(), true);

        EmailDetails mail = new EmailDetails(existingUser.getEmail(), "Your account have been deleted!!!\n\nIf this is not your action or you want to report please contact us.","Account Deletion");
        emailService.sendSimpleMail(mail);
        return "Successful restored user";
    }
}
