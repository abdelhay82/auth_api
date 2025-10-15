package com.apiauth.service.security;

import com.apiauth.entity.RefreshToken;
import com.apiauth.entity.User;
import com.apiauth.repository.RefreshTokenRepository;
import com.apiauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final SecurityAuditService auditService;

    @Value("${refresh-token-expiration}")
    private long refreshTokenExpiration;

    private final String REFRESH_TOKEN_CREATED = "refresh token created";

    public RefreshToken createRefreshToken(String email, String userAgent, String ipAddress){
        String tokenFamily = UUID.randomUUID().toString();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found exception"));
        RefreshToken refreshToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .tokenFamily(tokenFamily)
                .createdAt(Instant.now())
                .expiryDate(Instant.now().plusMillis(refreshTokenExpiration))
                .used(false)
                .revoked(false)
                .userAgent(userAgent)
                .ipAddress(ipAddress)
                .build();
        auditService.logEvent(email,REFRESH_TOKEN_CREATED, ipAddress, userAgent, "Token Family: " + tokenFamily );
        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public RefreshToken rotateRefreshToken(String token, String userAgent, String ipAddress){
        RefreshToken oldToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        if (oldToken.getUsed()){
            log.warn("SECURITY ALERT: Token reuse detected for user: {}", oldToken.getUser().getEmail());
            auditService.logSecurityIncident(oldToken.getUser().getEmail(), "Token reuse detected",
                    ipAddress, userAgent, "Token: "+token.substring(0,8)+"... Family "+ oldToken.getTokenFamily());
            revokeTokenFamily(oldToken.getTokenFamily());
        }

        if(oldToken.isExpired()){
            refreshTokenRepository.delete(oldToken);
            throw new RuntimeException("Refresh token is expired");
        }
        if (oldToken.getRevoked()){
            refreshTokenRepository.delete(oldToken);
            throw new RuntimeException("Refresh token expired");
        }
        oldToken.setUsed(true);
        oldToken.setLastUsedAt(Instant.now());
        refreshTokenRepository.save(oldToken);

        RefreshToken newToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .tokenFamily(oldToken.getTokenFamily())
                .user(oldToken.getUser())
                .createdAt(Instant.now())
                .expiryDate(Instant.now().plusMillis(refreshTokenExpiration))
                .userAgent(userAgent)
                .ipAddress(ipAddress)
                .build();

        log.info("Token rotated for user:{}", oldToken.getUser().getEmail());
        auditService.logEvent(oldToken.getUser().getEmail(), "TOKEN_ROTATED", ipAddress, userAgent,
                "Family: " + oldToken.getTokenFamily());
        return refreshTokenRepository.save(newToken);
    }

    public void revokeTokenFamily(String tokenFamily){
        List<RefreshToken> tokens = refreshTokenRepository.findByTokenFamily(tokenFamily);
        tokens.forEach(
                token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                }
                );
        log.warn("Revoked {} token in family: {}", tokens.size(), tokenFamily);
    }

    public void revokeRefreshToken(String token) {
        refreshTokenRepository.findByToken(token)
                .ifPresent(rt -> {
                    rt.setRevoked(true);
                    refreshTokenRepository.save(rt);
                });
    }

    @Scheduled(cron = "0 0 2 * * ?")
    @Transactional
    public void cleanUsedTokens(){
        Instant cutOff = Instant.now().minus(1, ChronoUnit.HOURS);
        int deleted = refreshTokenRepository.deleteUsedTokensOlderThan(cutOff);
        log.info("cleaned {} used refresh tokens", deleted);
    }

    @Scheduled(cron = "0 0 * * * ?")
    @Transactional
    public void cleanRevokedToken(){
        Instant cutOff = Instant.now().minus(1, ChronoUnit.HOURS);
        int deleted = refreshTokenRepository.deleteRevokedTokensOlderThan(cutOff);
        log.info("cleaned {} used revoked tokens", deleted);
    }

    @Scheduled(cron = "0 0 3 * * SUN")
    @Transactional
    public void cleanExpiredToken(){
        Instant cutOff = Instant.now().minus(1, ChronoUnit.HOURS);
        int deleted = refreshTokenRepository.deleteExpiredTokensOlderThan(cutOff);
        log.info("cleaned {} expired refresh tokens", deleted);
    }

}
