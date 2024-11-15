package com.LearnSpringSecurity.webtoken;

import com.LearnSpringSecurity.config.MyUserDetailService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;
    @Autowired
    private MyUserDetailService myUserDetailService;

    /*
    * The OncePerRequestFilter will execute once for every request,
    * so we can check weather do we need to authorize that request using the jwt token
    * The first Thing we need to check is the authorization header,
    *   - Get the header from the response
    *   - Check is the header is properly provided (null or the header doesn't start with Bearer) or not
    *   - if true, then token is not properly provided, ignore the request
    *   - if not, then get the jwt token from the header
    *   - Then extract the username from the token
    *   - Check two things, if the username != null and request is not already logged in.
    *       * we have to make sure that the current authentication is null before proceeding the authentication with jwt token
    *         because, if it is already authenticated then there is no need to authenticate the jwt again
    *   - After authentication, we have to find the user(UserDetails) with the username
    *   - make sure that the userDetails is not null and also validate the token
    *   - After the making sure the jwt token is valid, we will create a username-password-authentication-token (Creating it manually)
    *     then marking the context as logged in
    *
    *
    * */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException
    {
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        String jwt = authorizationHeader.substring(7); // 7 is the length of the "Bearer "
        String username = jwtService.extractUsername(jwt);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = myUserDetailService.loadUserByUsername(username);
            if (userDetails != null && jwtService.isTokenValid(jwt)){
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        username,
                        userDetails.getPassword(),
                        userDetails.getAuthorities()
                );
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
