package com.LearnSpringSecurity.controller;

import com.LearnSpringSecurity.config.MyUserDetailService;
import com.LearnSpringSecurity.model.LoginForm;
import com.LearnSpringSecurity.webtoken.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class ContentController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private MyUserDetailService myUserDetailService;

    @GetMapping("/home")
    public String handleWelcome(){
        return "home";
    }

    @GetMapping("/admin/home")
    public String handleAdminHome(){
        return "home_admin";
    }

    @GetMapping("/user/home")
    public String handleUserHome(){
        return "home_user";
    }

    @GetMapping("/login")
    public String handleLogin() {
        return "custom_login";
    }

    // When the user is logged in it will generate a token ( Authentication )
    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticateAndGetToken(@RequestBody LoginForm loginForm) {
        // First we have to authenticate the username and password that we are receiving from the loginForm,
        // for authentication we need Authentication Manager, we have to autowire it and create a bean of AuthenticationManager in the SecurityConfiguration class
        // it will help us to authenticate the username and password, so we don't have to write the logic separately
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        loginForm.username(), loginForm.password())
                );
        // Validating the user the username and password are correct(Authenticated)
        // if authenticated, return the token
        // else throw exception
        if (authentication.isAuthenticated()) {
            String token = jwtService.generateToken(myUserDetailService.loadUserByUsername(loginForm.username()));
            return ResponseEntity.ok(token);
        } else {
            throw new UsernameNotFoundException("Invalid username or password");
        }
    }



}
