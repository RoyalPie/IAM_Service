package com.example.IAM_Service.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OtpRequest {

    @NotBlank
    private String email;
    @NotBlank
    private String otp;
}
