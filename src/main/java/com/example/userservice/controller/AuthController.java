package com.example.userservice.controller;

import com.example.userservice.dto.LoginRequest;
import com.example.userservice.dto.RegisterRequest;
import com.example.userservice.model.AppUser;
import com.example.userservice.model.Role;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.service.UserService;
import com.example.userservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import com.example.userservice.service.EmailService;
import jakarta.servlet.http.HttpServletRequest;
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
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            // ✅ Auth passed, now get real AppUser for JWT
            AppUser user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            String token = jwtUtil.generateToken(user); // ✅ correct roles format

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("token", token));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("message", "Invalid credentials"));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String token) {
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);  // Remove "Bearer " prefix
        }

        userService.logout(token);
        return ResponseEntity.ok("✅ Logout successful!");
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("❌ User not found!"));

        // Generate Reset Token (Valid for 15 minutes)
        String resetToken = jwtUtil.generateResetToken(user);
        resetTokens.put(resetToken, email); // Store the token temporarily

        // Generate Reset Link
        String resetLink = "http://localhost:8081/auth/reset-password?token=" + resetToken;

        // Send Email with Reset Link
        String emailBody = "<h3>Password Reset Request</h3>"
                + "<p>Click the link below to reset your password:</p>"
                + "<a href='" + resetLink + "'>Reset Password</a>";

        emailService.sendEmail(email, "Password Reset Request", emailBody);

        return ResponseEntity.ok("✅ Password reset link sent to your email!");
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
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            AppUser user = new AppUser();
            user.setEmail(request.getEmail());
            user.setUsername(request.getUsername());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setRole(Role.valueOf(request.getRole())); // Role.USER or ADMIN, etc.

            userRepository.save(user);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("message", "✅ User registered successfully!"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("message", "❌ Registration failed: " + e.getMessage()));
        }
    }


}
