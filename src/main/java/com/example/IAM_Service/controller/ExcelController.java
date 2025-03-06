package com.example.IAM_Service.controller;

import com.example.IAM_Service.service.ExcelService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/excel")
public class ExcelController {
    @Autowired
    private ExcelService excelService;

    @GetMapping("/export")
    public ResponseEntity<byte[]> exportUsers() throws IOException {
        byte[] excelBytes = excelService.exportUsers();
        return ResponseEntity.ok().header("Content-Disposition", "attachment; filename=users.xlsx").body(excelBytes);
    }
    @PostMapping("/import")
    public ResponseEntity<List<String>> importUsers(@RequestParam("file") MultipartFile file) throws IOException {
        return ResponseEntity.ok(excelService.importUsers(file));
    }
}
