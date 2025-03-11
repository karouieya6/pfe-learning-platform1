package com.example.userservice.controller;

import com.example.userservice.dto.ChangePasswordRequest;
import com.example.userservice.model.AppUser;
import com.example.userservice.model.Role;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService  userService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    /**
     * ✅ Get Logged-in User Profile
     * 🔹 Only authenticated users can access this.
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        String email = authentication.getName();
        Optional<AppUser> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }

        AppUser user = userOpt.get();
        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "role", user.getRole().name()
        ));
    }
    /**
     * ✅ Get All Users
     * 🔹 Admins only
     */
    @GetMapping("/all")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> getAllUsers() {
        List<AppUser> users = userRepository.findAll();

        // Sanitize user data
        List<Map<String, Object>> sanitizedUsers = users.stream().map(user -> {
            Map<String, Object> userData = new HashMap<>();
            userData.put("id", user.getId());
            userData.put("username", user.getUsername());
            userData.put("email", user.getEmail());
            userData.put("role", user.getRole().name());
            return userData;
        }).collect(Collectors.toList());

        return ResponseEntity.ok(sanitizedUsers);
    }


    /**
     * ✅ Get User by ID
     * 🔹 Admins only
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<AppUser> getUserById(@PathVariable Long id) {
        Optional<AppUser> user = userRepository.findById(id);
        return user.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * ✅ Update User Info
     * 🔹 Admins only
     */
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable Long id, Authentication authentication) {
        String adminEmail = authentication.getName();
        userService.deleteUser(id, adminEmail);
        return ResponseEntity.ok("User deleted successfully!");
    }



    @PutMapping("/update/{id}")
    public ResponseEntity<String> updateUser(@PathVariable Long id,
                                             @RequestBody AppUser updatedUser,
                                             Authentication authentication) {
        String adminEmail = authentication.getName();
        AppUser adminUser = userRepository.findByEmail(adminEmail)
                .orElseThrow(() -> new RuntimeException("Admin not found"));

        if (!adminUser.getRole().name().equals("ADMIN")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied: Admin Role Required!");
        }

        AppUser user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setUsername(updatedUser.getUsername());
        user.setEmail(updatedUser.getEmail());
        user.setRole(updatedUser.getRole()); // Ensure roles are handled properly

        userRepository.save(user);
        return ResponseEntity.ok("✅ User updated successfully!");
    }




    @PutMapping("/profile")
    public ResponseEntity<?> updateUserProfile(Authentication authentication, @RequestBody Map<String, String> updates) {
        String email = authentication.getName();
        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (updates.containsKey("username")) user.setUsername(updates.get("username"));
        if (updates.containsKey("email")) user.setEmail(updates.get("email"));

        userRepository.save(user);
        return ResponseEntity.ok("✅ Profile updated successfully!");
    }
    @PutMapping("/change-password")
    public ResponseEntity<?> changePassword(Authentication authentication,
                                            @RequestBody Map<String, String> passwords) {
        String email = authentication.getName(); // Extract email from JWT
        System.out.println("🔹 Extracted email from JWT: " + email);

        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        System.out.println("✅ User found in database: " + user.getEmail());
        System.out.println("🔑 Hashed password in DB: " + user.getPassword());

        // Verify old password
        if (!passwordEncoder.matches(passwords.get("oldPassword"), user.getPassword())) {
            System.out.println("❌ Incorrect old password for: " + email);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("❌ Incorrect old password!");
        }

        System.out.println("🔄 Updating password for user: " + email);
        user.setPassword(passwordEncoder.encode(passwords.get("newPassword")));
        userRepository.save(user);

        return ResponseEntity.ok("✅ Password updated successfully!");
    }
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/deactivate/{id}")
    public ResponseEntity<String> deactivateUser(@PathVariable Long id, Authentication authentication) {
        String adminEmail = authentication.getName();
        userService.deactivateUser(id, adminEmail);
        return ResponseEntity.ok("User deactivated successfully!");
    }





}
