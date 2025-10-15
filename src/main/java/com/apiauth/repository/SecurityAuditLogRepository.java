package com.apiauth.repository;

import com.apiauth.entity.SecurityAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface SecurityAuditLogRepository extends JpaRepository<SecurityAuditLog, Long> {

    List<SecurityAuditLog> findByEmailOrderByTimestampDesc(String email);
    List<SecurityAuditLog> findByEventTypeAndTimestampAfter(String eventType, Instant after);
}
