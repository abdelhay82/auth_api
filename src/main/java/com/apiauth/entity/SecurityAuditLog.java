package com.apiauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Table(name = "security_audit_log")
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;
    @Column(nullable = false)
    private String eventType;

    private String ipAddress;
    private String userAgent;
    private String details;

    @Column(nullable = false)
    private Instant timeStamp;

    @PrePersist
    protected void onCreate(){
        if(timeStamp == null){
            timeStamp = Instant.now();
        }
    }
}
