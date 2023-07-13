package com.hab.security.config;

import com.hab.security.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(
        HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication
    ) {
        final String authHeader  = request.getHeader("Authorization");
        final String jwt;

        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        // extract jwt from authHeader, that is after Bearer (7) and userEmail from jwt token.
        jwt = authHeader.substring(7);
        var storedToken = tokenRepository.findByToken(jwt)
                .orElse(null);
        
        if(storedToken != null){
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
        }
    }
}
