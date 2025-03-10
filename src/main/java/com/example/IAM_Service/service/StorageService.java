package com.example.IAM_Service.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Service
public class StorageService {
    @Autowired
    private KeycloakService keycloakService;
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public Map<String, String> uploadFile(MultipartFile[] files, String email) throws IOException {
        String token = keycloakService.getStorageAccessToken();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        //Todos: Upload Multiple file
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        for (MultipartFile file : files) {
            body.add("file", new ByteArrayResource(file.getBytes()) {
                @Override
                public String getFilename() {
                    return file.getOriginalFilename(); // Ensure the filename is preserved
                }
            });
        }
        body.add("email", email);

        System.out.println(body.get("file"));
        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);
        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<String> response = restTemplate.exchange("http://localhost:8083/api/public/upload-image", HttpMethod.POST, request, String.class);

        List<Map<String, String>> resultList = objectMapper.readValue(
                response.getBody(),
                new TypeReference<List<Map<String, String>>>() {}
        );

        // Return the first object in the list
        return resultList.isEmpty() ? null : resultList.get(0);
    }
}
