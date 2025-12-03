package com.authserver.controller;

import com.authserver.dto.LoginRequest;
import com.authserver.dto.RegisterRequest;
import com.authserver.dto.RefreshTokenRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void register_Success() throws Exception {
        RegisterRequest request = RegisterRequest.builder()
                .username("testuser")
                .email("test@example.com")
                .password("password123")
                .firstName("Test")
                .lastName("User")
                .build();

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Registration successful"))
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andExpect(jsonPath("$.data.refreshToken").exists())
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"));
    }

    @Test
    void register_InvalidEmail_BadRequest() throws Exception {
        RegisterRequest request = RegisterRequest.builder()
                .username("testuser2")
                .email("invalid-email")
                .password("password123")
                .build();

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Validation Error"));
    }

    @Test
    void login_Success() throws Exception {
        // First register a user
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("loginuser")
                .email("login@example.com")
                .password("password123")
                .build();

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        // Then login
        LoginRequest loginRequest = LoginRequest.builder()
                .username("loginuser")
                .password("password123")
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Login successful"))
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andExpect(jsonPath("$.data.refreshToken").exists());
    }

    @Test
    void login_InvalidCredentials_Unauthorized() throws Exception {
        LoginRequest loginRequest = LoginRequest.builder()
                .username("nonexistent")
                .password("wrongpassword")
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void getUserInfo_Unauthorized_WhenNoToken() throws Exception {
        mockMvc.perform(get("/auth/userinfo"))
                .andExpect(status().isForbidden());
    }

    @Test
    void getUserInfo_Success_WithValidToken() throws Exception {
        // Register a user
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("infouser")
                .email("info@example.com")
                .password("password123")
                .firstName("Info")
                .lastName("User")
                .build();

        MvcResult registerResult = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andReturn();

        // Extract access token
        String response = registerResult.getResponse().getContentAsString();
        String accessToken = objectMapper.readTree(response).get("data").get("accessToken").asText();

        // Get user info with token
        mockMvc.perform(get("/auth/userinfo")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.username").value("infouser"))
                .andExpect(jsonPath("$.data.email").value("info@example.com"))
                .andExpect(jsonPath("$.data.firstName").value("Info"))
                .andExpect(jsonPath("$.data.lastName").value("User"));
    }

    @Test
    void refresh_Success() throws Exception {
        // Register a user
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("refreshuser")
                .email("refresh@example.com")
                .password("password123")
                .build();

        MvcResult registerResult = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andReturn();

        // Extract refresh token
        String response = registerResult.getResponse().getContentAsString();
        String refreshToken = objectMapper.readTree(response).get("data").get("refreshToken").asText();

        // Refresh token
        RefreshTokenRequest refreshRequest = RefreshTokenRequest.builder()
                .refreshToken(refreshToken)
                .build();

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andExpect(jsonPath("$.data.refreshToken").exists());
    }

    @Test
    void logout_Success() throws Exception {
        // Register a user
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("logoutuser")
                .email("logout@example.com")
                .password("password123")
                .build();

        MvcResult registerResult = mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andReturn();

        // Extract tokens
        String response = registerResult.getResponse().getContentAsString();
        String accessToken = objectMapper.readTree(response).get("data").get("accessToken").asText();
        String refreshToken = objectMapper.readTree(response).get("data").get("refreshToken").asText();

        // Logout
        RefreshTokenRequest logoutRequest = RefreshTokenRequest.builder()
                .refreshToken(refreshToken)
                .build();

        mockMvc.perform(post("/auth/logout")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Logout successful"));
    }
}
