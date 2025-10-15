package com.apiauth.service.security;

import com.apiauth.entity.SecurityAuditLog;
import com.apiauth.repository.SecurityAuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityAuditService {
    private final SecurityAuditLogRepository auditLogRepository;

    public void logEvent(String email, String eventType, String ipAddress, String userAgent, String details){
        SecurityAuditLog securityAuditLog = SecurityAuditLog.builder()
                .email(email)
                .eventType(eventType)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .details(details)
                .timeStamp(Instant.now())
                .build();

        auditLogRepository.save(securityAuditLog);
        log.info("Audit:{} - {} - {}", email, eventType, ipAddress);
    }

    public void logSecurityIncident(String email, String eventType, String ipAddress, String userAgent, String details){
        logEvent(email, eventType, ipAddress, userAgent, details);
        log.error("Security incident: {} - {} - {}", email, eventType, details);
    }
}
