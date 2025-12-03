package com.authserver.controller;

import com.authserver.dto.*;
import com.authserver.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /auth/login - Authenticate user and return tokens
     */
    @PostMapping("/login")
    public ResponseEntity<StandardResponse<TokenResponse>> login(
            @Valid @RequestBody LoginRequest request) {
        log.info("Login attempt for user: {}", request.getUsername());
        TokenResponse tokenResponse = authService.login(request);
        return ResponseEntity.ok(StandardResponse.success(tokenResponse, "Login successful"));
    }

    /**
     * POST /auth/register - Register a new user
     */
    @PostMapping("/register")
    public ResponseEntity<StandardResponse<TokenResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        log.info("Registration attempt for user: {}", request.getUsername());
        TokenResponse tokenResponse = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(StandardResponse.success(tokenResponse, "Registration successful"));
    }

    /**
     * POST /auth/refresh - Refresh access token using refresh token
     */
    @PostMapping("/refresh")
    public ResponseEntity<StandardResponse<TokenResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request) {
        log.info("Token refresh request");
        TokenResponse tokenResponse = authService.refresh(request);
        return ResponseEntity.ok(StandardResponse.success(tokenResponse, "Token refreshed successfully"));
    }

    /**
     * POST /auth/logout - Logout user and invalidate tokens
     */
    @PostMapping("/logout")
    public ResponseEntity<StandardResponse<Void>> logout(
            @Valid @RequestBody RefreshTokenRequest request) {
        log.info("Logout request");
        authService.logout(request.getRefreshToken());
        return ResponseEntity.ok(StandardResponse.success("Logout successful"));
    }

    /**
     * GET /auth/userinfo - Get current authenticated user info
     */
    @GetMapping("/userinfo")
    public ResponseEntity<StandardResponse<UserInfoResponse>> getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        log.info("User info request for: {}", username);
        UserInfoResponse userInfo = authService.getUserInfo(username);
        return ResponseEntity.ok(StandardResponse.success(userInfo, "User info retrieved successfully"));
    }
}
