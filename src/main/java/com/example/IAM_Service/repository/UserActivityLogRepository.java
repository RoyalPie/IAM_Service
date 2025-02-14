package com.example.IAM_Service.repository;

import com.example.IAM_Service.entity.User;
import com.example.IAM_Service.entity.UserActivityLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserActivityLogRepository extends JpaRepository<UserActivityLog, Long> {
    List<UserActivityLog> findByUser(User user);
}
