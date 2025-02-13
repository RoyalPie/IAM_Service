package com.example.IAM_Service.service;

import com.example.IAM_Service.dto.UserDto;
import com.example.IAM_Service.entity.EmailDetails;
import com.example.IAM_Service.entity.PasswordResetToken;
import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.jwt.JwtUtils;
import com.example.IAM_Service.payload.request.ChangePasswordRequest;
import com.example.IAM_Service.repository.PasswordTokenRepository;
import com.example.IAM_Service.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordTokenRepository passwordTokenRepository;

    @Autowired
    BCryptPasswordEncoder encoder;

    @Autowired
    private EmailService emailService;

    @Autowired
    private JwtUtils jwtUtils;

    public Optional<User> findbyEmail(String username) {
        return userRepository.findByEmail(username);
    }
    public Optional<PasswordResetToken> findbyToken(String token) {
        return passwordTokenRepository.findByToken(token);
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

        userRepository.save(existingUser);
        EmailDetails mail = new EmailDetails(existingUser.getEmail(), "Your password have been changed!!!\n\nIf this is not your action please contact us.","Successful Changed Password");
        emailService.sendSimpleMail(mail);
        return "Đổi mật khẩu thành công";
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
    public PasswordResetToken createPasswordResetTokenForUser(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
        if(passwordTokenRepository.existsByUser(user)){
            deleteByUser(user.getId());
        }
        passwordTokenRepository.flush();

        PasswordResetToken resetToken = new PasswordResetToken();

        resetToken.setUser(userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found")));
        try {
            resetToken.setToken(jwtUtils.generateToken(email));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        resetToken = passwordTokenRepository.save(resetToken);

        return resetToken;

    }
    public boolean verifyExpiration(PasswordResetToken token) {
        try {
            if (jwtUtils.isTokenExpired(token.getToken())) {
                passwordTokenRepository.delete(token);
                return false;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return true;
    }
    @Transactional
    public void deleteByUser(Long userId) {
        passwordTokenRepository.deleteByUser(userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found")));
    }
}
