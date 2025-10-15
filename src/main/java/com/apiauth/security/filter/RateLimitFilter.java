package com.apiauth.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
@Slf4j
public class RateLimitFilter extends OncePerRequestFilter {
    private static final int MAX_REQUESTS = 100;
    private static final long TIME_WINDOW = 60000;

    private final Map<String, CopyOnWriteArrayList<Long>> requestCounts = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String clientIp = request.getRemoteAddr();
        long now = System.currentTimeMillis();

        requestCounts.putIfAbsent(clientIp, new CopyOnWriteArrayList<>());
        CopyOnWriteArrayList<Long> timeStamps = requestCounts.get(clientIp);
        timeStamps.removeIf(time -> now - time > TIME_WINDOW);
        if(timeStamps.size() >= MAX_REQUESTS){
            log.warn("Rate limit exceeded for IP: {}", clientIp);
            response.setStatus(429);
            response.getWriter().write("Rate limit exceeded, Tray again later");
            return;
        }
        timeStamps.add(now);
        filterChain.doFilter(request, response);
    }
}
