package com.apiauth.service.auth;

import com.apiauth.dto.LoginRequest;
import com.apiauth.dto.LoginResponse;
import com.apiauth.dto.RegisterRequest;
import com.apiauth.entity.RefreshToken;
import com.apiauth.entity.User;
import com.apiauth.enums.Role;
import com.apiauth.mapper.UserMapper;
import com.apiauth.repository.UserRepository;
import com.apiauth.service.security.JwtService;
import com.apiauth.service.security.RefreshTokenService;
import com.apiauth.service.security.SecurityAuditService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final SecurityAuditService auditService;
    private final UserMapper userMapper;

    public Map<String, String> register(RegisterRequest request){
        if (userRepository.existByEmail(request.getEmail())){
            throw  new RuntimeException("Email.already exist");
        }

        User user = userMapper.toUser(request);
        user.setRole(Role.USER);
        userRepository.save(user);
        if(!(request instanceof HttpServletRequest httpRequest)){
            throw new RuntimeException("bad request");
        }
        auditService.logEvent(request.getEmail(),"USER_REGISTERED", getClientIp(httpRequest), httpRequest.getHeader("User-Agent"),null);
        return Map.of("response", "User Registered successfully");
    }

    public LoginResponse login(
            LoginRequest request,
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse){
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow();
            user.setLastLoginAt(Instant.now());
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
            String accessToken = jwtService.generateAccessToken(user);
            String userAgent = httpServletRequest.getHeader("User-Agent");
            String ipAddress = getClientIp(httpServletRequest);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(request.getEmail(), userAgent, ipAddress);
            addRefreshTokenCookie(httpServletResponse, refreshToken.getToken());

            auditService.logEvent(request.getEmail(), "LOGIN_SUCCESS", ipAddress, userAgent, null);

            return LoginResponse.builder()
                    .accessToken(accessToken)
                    .tokenType("Bearer")
                    .expiresIn(900)
                    .build();
        }  catch ( Exception e){
            User user = userRepository.findByEmail(request.getEmail()).orElse(null);
            if(user != null){
                user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
                userRepository.save(user);
            }
            auditService.logSecurityIncident(request.getEmail(), "LOGIN_FAILED", getClientIp(httpServletRequest), httpServletRequest.getHeader("User-Agent"), e.getMessage());
        }
        return null;

    }

    public LoginResponse refresh(
            String oldRefreshToken,
            HttpServletRequest request,
            HttpServletResponse response
    ){
        try {
            String userAgent = request.getHeader("User-Agent");
            String ipAddress = getClientIp(request);
            RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(
                    oldRefreshToken, userAgent, ipAddress
            );
            String newAccessToken = jwtService.generateAccessToken(newRefreshToken.getUser());
            addRefreshTokenCookie(response, newRefreshToken.getToken());
            return LoginResponse.builder()
                    .accessToken(newAccessToken)
                    .tokenType("Bearer")
                    .expiresIn(9000)
                    .build();
        }catch (Exception e){
            clearRefreshTokenCookie(response);
            return  null;
        }
    }

    public Map<String, String> logOut(
            String refreshToken,
            HttpServletRequest request,
            HttpServletResponse response
    ){
        if(refreshToken != null){
            refreshTokenService.revokeRefreshToken(refreshToken);
            auditService.logEvent("user", "logout", getClientIp(request), request.getHeader("User-Agent"), null);
        }
        clearRefreshTokenCookie(response);
        return Map.of("response", "Success Logout");
    }

    private void addRefreshTokenCookie(HttpServletResponse response, String token){
        Cookie cookie = new Cookie("refreshToken", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/auth");
        cookie.setMaxAge(30 * 24 *60 *60);
        response.addCookie(cookie);
    }

    private void clearRefreshTokenCookie(HttpServletResponse response){
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/auth");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private String getClientIp(HttpServletRequest request){
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if(xForwardedFor != null && !xForwardedFor.isEmpty()){
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
