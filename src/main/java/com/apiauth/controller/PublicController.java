package com.apiauth.controller;

import com.apiauth.service.PublicService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class PublicController {

    private final PublicService publicService;

    @GetMapping("/products")
    public ResponseEntity<Map<String, Object>> getProducts(Authentication authentication, HttpServletRequest request){
        return ResponseEntity.ok(publicService.getProduct(authentication, request));
    }

    @GetMapping("/welcome")
    public ResponseEntity<Map<String, Object>> welcome(Authentication authentication){
        return ResponseEntity.ok(publicService.welcome(authentication));
    }

    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getProfile(UserDetails userDetails){
        return ResponseEntity.ok(publicService.getProfile(userDetails));
    }
}
