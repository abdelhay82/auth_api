package com.apiauth.service;

import com.apiauth.service.auth.AnonymousUserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class PublicService {
    private final AnonymousUserService anonymousUserService;

    public Map<String, Object> getProduct(
            Authentication authentication,
            HttpServletRequest request
    ){
        Map<String, Object> response = new HashMap<>();
        if(authentication instanceof AnonymousAuthenticationToken){
            String sessionId = (String) request.getAttribute("anonymousSessionId");

            response.put("userType", "anonymous");
            response.put("sessionId", sessionId);
            response.put("message", "Browsing as anonymous user");
            response.put("callToAction", "Register to save your preferences!");
        }else {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            response.put("userType", "authenticated");
            response.put("username", userDetails.getUsername());
            response.put("message", "Browsing as authenticated user");
        }
        response.put("products", List.of(
                Map.of("id", 1, "name", "product1", "price", 1000),
                Map.of("id", 2, "name", "product2", "price", 1500)
        ));
        return response;
    }

    public Map<String, Object> welcome(Authentication authentication){
        Map<String, Object> response = new HashMap<>();
        if(authentication instanceof AnonymousAuthenticationToken){
            response.put("message", "Welcome!");
            response.put("features", List.of("Brows products", "View articles", "Search content"));
            response.put("limitedAccess", true);
            response.put("prompt", "Sign up to unlock full features!");
        }else {
            UserDetails user = (UserDetails) authentication.getPrincipal();
            response.put("message", "Welcome back, " + user.getUsername());
            response.put("features", List.of(
                    "Brows products",
                    "View articles",
                    "Search content",
                    "Save favorites",
                    "Write reviews",
                    "Track orders"
            ));
            response.put("limitedAccess", false);
        }
        return response;
    }

    public Map<String, Object> getProfile(
            @AuthenticationPrincipal UserDetails userDetails
    ){
        Map<String, Object> response = new HashMap<>();

        response.put("email", userDetails.getUsername());
        response.put("authorities", userDetails.getAuthorities());
        response.put("message", "Authenticated user profile");
        return response;
    }
}
