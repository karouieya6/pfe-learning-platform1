package com.example.userservice.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String username;
    private String email;
    private String password;
    private String role;  // Role should be passed as "ROLE_STUDENT", "ROLE_ADMIN", etc.
}
