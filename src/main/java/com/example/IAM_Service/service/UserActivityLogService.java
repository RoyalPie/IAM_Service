package com.example.IAM_Service.service;

import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.entity.UserActivityLog;
import com.example.IAM_Service.repository.UserActivityLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserActivityLogService {

    @Autowired
    private UserActivityLogRepository userActivityLogRepository;

    public void logActivity(User user, String action, String ipAddress, String userAgent) {
        UserActivityLog log = new UserActivityLog(user, action, ipAddress, userAgent);
        userActivityLogRepository.save(log);
    }
}
