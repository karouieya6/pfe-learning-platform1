package com.example.userservice.repository;

import com.example.userservice.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByEmail(String email);
    boolean existsByEmail(String email);

    // Add this method to find active users
    List<AppUser> findByActiveTrue(); // Only return active users
}
