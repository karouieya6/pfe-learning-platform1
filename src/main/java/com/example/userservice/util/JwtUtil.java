package com.example.userservice.util;

import com.example.userservice.model.AppUser;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long expirationTime;

    public String generateToken(AppUser user) {
        return Jwts.builder()
                .setSubject(user.getEmail())  // Keep email in "sub"
                .claim("role", user.getRole().name()) // Store role (without "ROLE_" prefix)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime)) // Token expiry
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }





    public String extractUsername(String token) {
        String email = extractClaim(token, Claims::getSubject);
        System.out.println("📌 Extracted email from JWT: " + email);
        return email;
    }


    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token, String userEmail) {
        final String username = extractUsername(token);
        return (username.equals(userEmail) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }
    public String generateResetToken(AppUser user) {
        return Jwts.builder()
                .setSubject(user.getEmail())  // Email as subject
                .claim("reset", true) // Mark this as a reset token
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + (15 * 60 * 1000))) // 15 minutes expiry
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

}
