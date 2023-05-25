package com.jwt.security.auth;

import com.jwt.security.config.JwtService;
import com.jwt.security.user.User;
import com.jwt.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.rest.webmvc.ResourceNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authService;
    private final JwtService jwtService;
    private final UserRepository userRepository;


    //retrieves name from jwt token, will be called from frontend to use the first name
    @PostMapping("/{jwt}")
    public ResponseEntity<String> firstNameFromJwt(
            @PathVariable String jwt
    ){
        String email = jwtService.extractUsername(jwt);
        Optional<User> user= userRepository.findByEmail(email);
        String firstName = user.get().getFirstName(); //zidi ispresent() check
        return ResponseEntity.ok(firstName);
    }


    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ){
        return  ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody AuthenticationRequest request
    ){
        return ResponseEntity.ok(authService.authenticate(request));
    }

    @GetMapping("users/list")
    public List<User> getRapportList(){
        List<User> usersList= new ArrayList<User>();
        userRepository.findAll().forEach(users -> usersList.add(users));
        return usersList;
    }


    @GetMapping("users/{id}")
    public ResponseEntity<User> findUserById(@PathVariable Long id) {
        User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found with id " + id));
        if (user!=null) {
            return new ResponseEntity<>(user, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

}
