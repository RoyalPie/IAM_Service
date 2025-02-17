package com.example.IAM_Service.service;

import com.example.IAM_Service.entity.EmailDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    @Autowired
    private JavaMailSender javaMailSender;

    @Value("${spring.mail.username}") private String sender;
    public String sendSimpleMail(EmailDetails details)
    {
        try {

            SimpleMailMessage mailMessage
                    = new SimpleMailMessage();

            mailMessage.setFrom(sender);
            mailMessage.setTo(details.getRecipient());
            mailMessage.setText(details.getMsgBody());
            mailMessage.setSubject(details.getSubject());

            javaMailSender.send(mailMessage);
            return "Mail Sent Successfully...";
        }
        catch (Exception e) {
            return "Error while Sending Mail";
        }
    }
    public String sendOtpEmail(String email, String otp)
    {
        EmailDetails details = new EmailDetails();
        try {

            SimpleMailMessage mailMessage
                    = new SimpleMailMessage();

            mailMessage.setFrom(sender);
            mailMessage.setTo(email);
            mailMessage.setText("Your OTP code is: "+otp+"\nPlease don't share this with anyone");
            mailMessage.setSubject("OTP SignIn Code");

            javaMailSender.send(mailMessage);
            return "Mail Sent Successfully...";
        }

        catch (Exception e) {
            return "Error while Sending Mail";
        }
    }
}
