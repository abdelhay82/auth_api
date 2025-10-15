package com.apiauth.repository;

import com.apiauth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);
    List<RefreshToken> findByTokenFamily(String tokenFamily);
    List<RefreshToken> findByUserId(Long userId);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.userId= :userId")
    void deleteByUserId(@Param("userId") Long userId);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.used = true AND rt.lastUsedAt < :cutOff")
    int deleteUsedTokensOlderThan(@Param("cutOff") Instant cutOff);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.revoked = true And rt.lasUsedAt <:cutOff")
    int deleteRevokedTokensOlderThan(@Param("cutOff") Instant cutOff);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :cutOff")
    int deleteExpiredTokensOlderThan(@Param("cutOff") Instant cutOff);

    long countByUsedTrue();
    long countByRevokedTrue();
    long countByUsedFalseAndRevokedFalse();
}
