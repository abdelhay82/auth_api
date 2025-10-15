package com.apiauth.controller;

import com.apiauth.dto.LoginRequest;
import com.apiauth.dto.LoginResponse;
import com.apiauth.dto.RegisterRequest;
import com.apiauth.service.auth.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse) {
        return ResponseEntity.ok(authService.login(request, httpServletRequest, httpServletResponse));
    }

    public ResponseEntity<LoginResponse> refresh(
            @CookieValue(name = "refreshToken") String oldRefreshToken,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        return ResponseEntity.ok(authService.refresh(oldRefreshToken, request, response));
    }

    public ResponseEntity<Map<String, String>> logOut(
            @CookieValue(name = "refreshToken") String refreshToken,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        return ResponseEntity.ok(authService.logOut(refreshToken, request, response));
    }
}
