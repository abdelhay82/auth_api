package com.apiauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.yaml.snakeyaml.util.EnumUtils;

import java.time.Instant;

@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_token", columnList = "token"),
        @Index(name = "idx_token_family", columnList = "tokenFamily"),
        @Index(name = "idx_user_id", columnList = "user_id")
}
)
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String token;

    @ManyToOne
    @Column(nullable = false)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false)
    private String tokenFamily;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private Instant createdAt;

    private Instant lastUsedAt;

    @Builder.Default
    @Column(nullable = false)
    private Boolean used = false;

    @Builder.Default
    @Column(nullable = false)
    private Boolean revoked = false;

    private String userAgent;
    private String ipAddress;

    public Boolean isExpired(){
        return expiryDate.isBefore(Instant.now());
    }

    @PrePersist
    protected void onCreate(){
        if(createdAt == null){
            createdAt = Instant.now();
        }
    }
}
