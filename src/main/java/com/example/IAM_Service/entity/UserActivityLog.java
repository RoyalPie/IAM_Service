package com.example.IAM_Service.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "user_activity_logs")
public class UserActivityLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private String action;

    @Column(nullable = false, updatable = false, insertable = false, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private LocalDateTime timestamp;

    private String ipAddress;
    private String userAgent;

    public UserActivityLog(User user, String action, String ipAddress, String userAgent) {
        this.user = user;
        this.action = action;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
    }
}
