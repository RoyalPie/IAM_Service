package com.example.IAM_Service.controller;
import com.example.IAM_Service.entity.EmailDetails;
import com.example.IAM_Service.entity.PasswordResetToken;
import com.example.IAM_Service.payload.response.MessageResponse;
import com.example.IAM_Service.service.EmailService;
import com.example.IAM_Service.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/test")
@RestController
public class EmailController {
    @Autowired
    private EmailService emailService;

    @Autowired
    private UserService userService;

    @PostMapping("/sendMail")
    public String sendMail(@RequestBody EmailDetails details)
    {
        return emailService.sendSimpleMail(details);
    }
}
