package com.example.IAM_Service.service.logoutService;

import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.jwt.JwtUtils;
import com.example.IAM_Service.payload.response.MessageResponse;
import com.example.IAM_Service.repository.UserRepository;
import com.example.IAM_Service.service.IService.LogoutService;
import com.example.IAM_Service.service.JwtTokenBlackListService;
import com.example.IAM_Service.service.refreshTokenService.RefreshTokenService;
import com.example.IAM_Service.service.UserActivityLogService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service("customLogoutService")
@RequiredArgsConstructor
public class CustomLogoutService implements LogoutService {
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final UserActivityLogService userActivityLogService;
    private final RefreshTokenService refreshTokenService;
    private final JwtTokenBlackListService blackListService;

    @Override
    public ResponseEntity<?> logout(HttpServletRequest request) throws Exception {
        String email = jwtUtils.extractEmail(jwtUtils.extractTokenFromRequest(request));
        User user = userRepository.findByEmail(email).orElseThrow(()->new UsernameNotFoundException("User not found: " + email));
        refreshTokenService.deleteByUser(user.getEmail());
        blackListService.addToBlacklist(request);
        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        userActivityLogService.logActivity(user, "LOGOUT", ip, userAgent);
        return ResponseEntity.ok(new MessageResponse("Logout successfully"));
    }

}
