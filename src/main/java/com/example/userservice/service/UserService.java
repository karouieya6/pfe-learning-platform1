package com.example.userservice.service;

import com.example.userservice.dto.LoginRequest;
import com.example.userservice.dto.RegisterRequest;
import com.example.userservice.model.AppUser;
import com.example.userservice.model.Role;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.util.JwtUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;  // ✅ Use the new service

    @Transactional
    public String register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("❌ Email is already in use!");
        }

        AppUser user = new AppUser();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        try {
            user.setRole(Role.valueOf(request.getRole()));
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("❌ Invalid role provided!");
        }

        userRepository.save(user);
        return "✅ User registered successfully!";
    }

    public String login(LoginRequest request) {
        AppUser user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        return jwtUtil.generateToken(user);
    }

    // ✅ Use TokenBlacklistService
    public void logout(String token) {
        tokenBlacklistService.revokeToken(token);
    }

    public List<AppUser> getAllActiveUsers() {
        return userRepository.findByActiveTrue();}


    public AppUser getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("❌ User not found!"));
    }

    public AppUser updateUser(Long id, AppUser updatedUser) {
        AppUser user = getUserById(id);
        user.setUsername(updatedUser.getUsername());
        user.setEmail(updatedUser.getEmail());
        user.setRole(updatedUser.getRole());
        return userRepository.save(user);
    }

    @Transactional
    public void deleteUser(Long userId, String adminEmail) {
        AppUser adminUser = userRepository.findByEmail(adminEmail)
                .orElseThrow(() -> new RuntimeException("Admin not found"));

        // Only allow admin to delete users
        if (!adminUser.getRole().equals(Role.ADMIN)) {
            throw new RuntimeException("Access Denied: Admin role required");
        }

        AppUser userToDelete = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Delete user from database
        userRepository.delete(userToDelete);
    }

    @Transactional
    public void deactivateUser(Long userId, String adminEmail) {
        AppUser adminUser = userRepository.findByEmail(adminEmail)
                .orElseThrow(() -> new RuntimeException("Admin not found"));

        // Only allow admin to deactivate users
        if (!adminUser.getRole().equals(Role.ADMIN)) {
            throw new RuntimeException("Access Denied: Admin role required");
        }

        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Mark user as inactive
        user.setActive(false);
        userRepository.save(user); // Save the updated user
    }


}
