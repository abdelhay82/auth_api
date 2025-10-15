package com.apiauth.security.filter;

import com.apiauth.entity.AnonymousSession;
import com.apiauth.service.auth.AnonymousUserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

@Component
@RequiredArgsConstructor
@Slf4j
public class AnonymousUserTrackingFilter extends OncePerRequestFilter {

    private final AnonymousUserService anonymousUserService;
    private static final String ANONYMOUS_SESSION_COOKIE = "anonymous_session_id";
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if(auth instanceof AnonymousAuthenticationToken || auth == null){
            String sessionId = getAnonymousSessionId(request);
            String ipAddress = getClientIp(request);
            String userAgent = request.getHeader("User-Agent");

            AnonymousSession session = anonymousUserService.getOrCreateSession(sessionId, ipAddress, userAgent);

            if(!session.getSessionId().equals(sessionId)){
                addAnonymousSessionCookie(response, session.getSessionId());
            }
            request.setAttribute("anonymousSessionId", session.getSessionId());
            log.debug("Anonymous user tracked: {}", session.getSessionId());
        }
        filterChain.doFilter(request, response);
    }

    private String getAnonymousSessionId(HttpServletRequest request){
        Cookie[] cookies = request.getCookies();
        if(cookies != null){
            return Arrays.stream(cookies)
                    .filter(cookie -> cookie.getName().equals(ANONYMOUS_SESSION_COOKIE))
                    .findFirst()
                    .map(Cookie::getValue)
                    .orElse(null);
        }
        return null;
    }

    private void addAnonymousSessionCookie(HttpServletResponse response, String sessionId){
        Cookie cookie = new Cookie(ANONYMOUS_SESSION_COOKIE, sessionId);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // en production on mets true avec https
        cookie.setPath("/");
        cookie.setMaxAge(30 * 24 * 60 * 60);
        response.addCookie(cookie);
    }

    private String getClientIp(HttpServletRequest request){
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if(xForwardedFor != null && !xForwardedFor.isEmpty()){
            return xForwardedFor.split(",")[0].trim();
        }
        return  request.getRemoteAddr();
    }
}
