package com.example.userservice.config;

import com.example.userservice.service.CustomUserDetailsService;
import com.example.userservice.service.TokenBlacklistService;
import com.example.userservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService; // ✅ Use TokenBlacklistService instead of UserService

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()) // Disable CSRF for API requests
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/auth/register", "/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/forgot-password", "/auth/reset-password").permitAll()
                        .requestMatchers(HttpMethod.GET, "/user/profile", "/user/change-password").authenticated()
                        .requestMatchers(HttpMethod.GET, "/user/all", "/user/{id}").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/user/update/{id}").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/user/delete/{id}").hasAuthority("ADMIN")
                        .requestMatchers("/auth/logout").authenticated()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JwtAuthFilter(jwtUtil, userDetailsService, tokenBlacklistService),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
