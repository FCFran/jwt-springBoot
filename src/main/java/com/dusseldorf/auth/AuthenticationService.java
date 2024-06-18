package com.dusseldorf.auth;

import com.dusseldorf.Respository.RoleRepository;
import com.dusseldorf.Respository.UserRepository;
import com.dusseldorf.model.Role;
import com.dusseldorf.model.User;
import com.dusseldorf.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public void register(RegistrationRequest request) {

        var userRole = roleRepository.findAllById(request.getRoles().stream().map(Role::getId).toList());

        //todo - better exception handling -> MANEJO DE EXCEPCIONES
        //.orElseThrow(() -> new IllegalStateException("ROLE USER was not initialized"));
        if (userRole.size() == request.getRoles().size()) {
            var user = User.builder()
                    .firstname(request.getFirstname())
                    .lastname(request.getLastname())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .roles(userRole)
                    .build();

            userRepository.save(user);
        }
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var claims = new HashMap<String, Object>();
        var user = ((User) auth.getPrincipal());
        claims.put("fullName", user.fullName());

        var jwtToken = jwtService.generateToken(claims, user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }


}
