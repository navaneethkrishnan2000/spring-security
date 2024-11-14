package com.LearnSpringSecurity.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;

public class AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws ServletException, IOException {
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN")); // we have to use the string ROLE_ADMIN
        System.out.println(isAdmin);
        if (isAdmin){
            setDefaultTargetUrl("/admin/home");
        } else {
            setDefaultTargetUrl("/user/home");
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
 /*
 if we want to redirect to the user home page when we are signing in using user credentials,
 and if we want to redirect to admin homepage when we are signing in using admin credentials instead of any other page,
 we can set it using SuccessHandlers.
  */