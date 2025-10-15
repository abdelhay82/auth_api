package com.apiauth.service.auth;

import com.apiauth.entity.AnonymousSession;
import com.apiauth.repository.AnonymousSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AnonymousUserService {

    private final AnonymousSessionRepository anonymousSessionRepository;

    public AnonymousSession getOrCreateSession(String sessionId, String ipAddress, String userAgent){
        if(sessionId == null || sessionId.isEmpty()){
            return createNewSession(ipAddress, userAgent);
        }
        Optional<AnonymousSession> existing = anonymousSessionRepository.findBySessionId(sessionId);
        if(existing.isPresent()){
            AnonymousSession session = existing.get();
            session.setLastActivityAt(Instant.now());
            session.setPageViews(session.getPageViews() + 1);
            return anonymousSessionRepository.save(session);
        }
        return createNewSession(ipAddress, userAgent);
    }

    private AnonymousSession createNewSession(String ipAddress, String userAgent){
        AnonymousSession anonymousSession = AnonymousSession.builder()
                .sessionId(UUID.randomUUID().toString())
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .pageViews(1)
                .build();
        log.info("New anonymous session created: {}", anonymousSession.getSessionId());
        return anonymousSessionRepository.save(anonymousSession);
    }

    @Transactional
    public void convertToRegisteredUser(String sessionId, Long userId){
        anonymousSessionRepository.findBySessionId(sessionId).ifPresent(session -> {
            session.setConverted(true);
            session.setConvertedUserId(userId);
            anonymousSessionRepository.save(session);

            log.info("Anonymous user converted: {} -> User ID: {}", sessionId, userId);
        });
    }
    @Scheduled(cron = "0 0 3 * * ?")
    @Transactional
    public void cleanInactiveSession(){
        Instant cutoff = Instant.now().minus(3, ChronoUnit.DAYS);
        int deleted = anonymousSessionRepository.deleteInactiveSession(cutoff);
        log.info("Cleaned {} inactive anonymous sessions", deleted);
    }

    @Scheduled(cron = "0 0 * * *?")
    public void logStatistics(){
        long total = anonymousSessionRepository.count();
        long today = anonymousSessionRepository.countByCreatedAfter(
                Instant.now().minus(1, ChronoUnit.DAYS)
        );
        long converted = anonymousSessionRepository.countByConvertedTrue();
        log.info("Anonymous Stats - Total:{}, Today: {}, converted: {}", total, today,converted);
    }
}
