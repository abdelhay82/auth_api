package com.apiauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Table(name = "anonymous_session")
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AnonymousSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String sessionId;

    private String ipAddress;
    private String userAgent;
    private String country;

    @Column(nullable = false)
    private Instant createdAt;
    private Instant lastActivityAt;

    @Column(nullable = false)
    @Builder.Default
    private int pageViews = 0;

    @Builder.Default
    private boolean converted = false;

    private Long convertedUserId;

    @PrePersist
    protected void onCreate(){
        createdAt = Instant.now();
        lastActivityAt = Instant.now();
    }
}


