package com.jwt.security.auth;

import com.jwt.security.config.JwtService;
import com.jwt.security.user.Role;
import com.jwt.security.user.User;
import com.jwt.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        // Checking if email is unique
        if (repository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.admin) //nahhiha enum mnna w nwlli nb3tha f request m3a email and psw with the body
                .build();

        // Saving user to repository : user registered
        repository.save(user);

        // Creating JWT token for the created user
        var jwtToken = jwtService.generateToken(user);

        // Return authentication response with JWT token(its only property)
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
        );//valid credentials
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        //creating the jwt token for the existing user
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
