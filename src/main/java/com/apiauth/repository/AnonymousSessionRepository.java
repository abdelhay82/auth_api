package com.apiauth.repository;

import com.apiauth.entity.AnonymousSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;

public interface AnonymousSessionRepository extends JpaRepository<AnonymousSession, Long> {
    Optional<AnonymousSession> findBySessionId(String sessionId);

    @Modifying
    @Query("DELETE FROM AnonymousSession a WHERE a.lastActivityAt < :cutoff")
    int deleteInactiveSession(Instant cutoff);

    long countByCreatedAfter(Instant after);
    long countByConvertedTrue();
}
