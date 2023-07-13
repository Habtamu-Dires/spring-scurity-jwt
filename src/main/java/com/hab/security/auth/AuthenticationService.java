package com.hab.security.auth;

import com.hab.security.config.JwtService;
import com.hab.security.token.Token;
import com.hab.security.token.TokenRepository;
import com.hab.security.token.TokenType;
import com.hab.security.user.Role;
import com.hab.security.user.User;
import com.hab.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;

    private final UserRepository repository;
    private final TokenRepository tokenRepository;

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        var savedUser = repository.save(user);

        var jwtToken = jwtService.generateToken(user);

        //save token
        saveUserToken(savedUser, jwtToken);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }



    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        ); //in case the email or password not correct an exception will be thrown
        //so at this point the user is authenticated
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();

        revokeAllUserToken(user);

        var jwtToken = jwtService.generateToken(user);

        //save token
        saveUserToken(user, jwtToken);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    private void revokeAllUserToken(User user){
        var validUserToken = tokenRepository.findAllValidTokenByUser(user.getId());
        if(validUserToken.isEmpty())
            return;
        validUserToken.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });

        tokenRepository.saveAll(validUserToken);
    }


    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();

        tokenRepository.save(token);
    }
}
