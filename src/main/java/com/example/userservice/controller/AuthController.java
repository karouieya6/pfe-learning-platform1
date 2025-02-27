package com.example.userservice.controller;

import com.example.userservice.dto.LoginRequest;
import com.example.userservice.dto.RegisterRequest;
import com.example.userservice.model.AppUser;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.service.UserService;
import com.example.userservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final Map<String, String> resetTokens = new HashMap<>();

    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(userService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(userService.login(request));
    }
    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("❌ User not found!"));

        // Generate Reset Token (Valid for 15 minutes)
        String resetToken = jwtUtil.generateResetToken(user);

        // Store token temporarily (simulate database storage)
        resetTokens.put(resetToken, email);

        // Simulate Email Sending (Show link in console for testing)
        String resetLink = "http://localhost:8081/auth/reset-password?token=" + resetToken;
        System.out.println("🔗 Password Reset Link: " + resetLink);

        return ResponseEntity.ok("✅ Password reset link generated! (Check console)");
    }
    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("newPassword");

        if (!resetTokens.containsKey(token)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("❌ Invalid or expired token!");
        }

        String email = resetTokens.get(token);
        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("❌ User not found!"));

        // Update password securely
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Remove token after use
        resetTokens.remove(token);

        return ResponseEntity.ok("✅ Password updated successfully!");
    }


}
