package com.LearnSpringSecurity.config;

import com.LearnSpringSecurity.model.MyUser;
import com.LearnSpringSecurity.repository.MyUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MyUserDetailService implements UserDetailsService { // we are creating a custom user details service

    @Autowired
    private MyUserRepository myUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //First, Find the user from db
        // If the user is present then we will prepare the user details for the user, else throw an exception
        Optional<MyUser> user = myUserRepository.findByUsername(username);
        if(user.isPresent()){
            var userObj = user.get();
           return User.builder()
                   .username(userObj.getUsername())
                   .password(userObj.getPassword())
                   .roles(getRoles(userObj))
                   .build();
        } else {
            throw new UsernameNotFoundException(username);
        }
    }

    private String[] getRoles(MyUser user) {
        // If role is empty then return the role as Empty
        // else
        if(user.getRole() == null) {
            return new String[]{"USER"};
        }
        return user.getRole().split(",");
    }
}
