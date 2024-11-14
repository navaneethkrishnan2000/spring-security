package com.LearnSpringSecurity.controller;

import com.LearnSpringSecurity.model.MyUser;
import com.LearnSpringSecurity.repository.MyUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RegistrationController {

    @Autowired
    private MyUserRepository myUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register/user")
    public MyUser createUser(@RequestBody MyUser user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return myUserRepository.save(user);
    }
    /* while creating a new user through postman after entering the username, password and role, when I click the send button it returns a sign-in page of spring security. to avoid that we need to provide the "permitAll()" function to the url "/register/user"
        inorder to do that go to security config class and make some changes in the security filter chain method "registry.requestMatchers("/home", "/register/**").permitAll();" add the url to it. when we are going to send the request again, it will fail. because .
        because there is another set-up is here called csrf (Cross-Site Request Forgery) - Spring boot by default enables  csrf protection for POST requests. This mean it adds an extra layer of security to prevent unauthorized actions on your behalf, even if an attacker manages to steal  your session cookie
        so we need to disable it
     */

}
