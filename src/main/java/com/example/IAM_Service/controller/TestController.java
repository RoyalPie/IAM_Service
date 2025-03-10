package com.example.IAM_Service.controller;
import com.example.IAM_Service.entity.EmailDetails;
import com.example.IAM_Service.service.CloudinaryService;
import com.example.IAM_Service.service.EmailService;
import com.example.IAM_Service.service.StorageService;
import com.example.IAM_Service.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@RequestMapping("/api/test")
@RestController
@RequiredArgsConstructor
public class TestController {
    @Autowired
    private EmailService emailService;

    @Autowired
    private UserService userService;

    private final CloudinaryService cloudinaryService;

    private final StorageService storageService;

    @PostMapping("/cloudinary/upload")
    public ResponseEntity<Map> uploadImage(@RequestParam("image") MultipartFile file) {
        Map data = this.cloudinaryService.upload(file);
        String imageUrl = data.get("secure_url").toString();
        return new ResponseEntity<>(data, HttpStatus.OK);
    }
//    @PostMapping("/storage/upload")
//    public ResponseEntity<String> uploadStorage(@RequestParam("image") MultipartFile file) throws IOException {
//        return storageService.uploadFile(file, "omagateemo1711@gmail.com");
//    }


    @PostMapping("/sendMail")
    public String sendMail(@RequestBody EmailDetails details) {
        return emailService.sendSimpleMail(details);
    }

    @GetMapping("/exception")
    public String throwException() {
        throw new RuntimeException("This is a test exception!");
    }
}
