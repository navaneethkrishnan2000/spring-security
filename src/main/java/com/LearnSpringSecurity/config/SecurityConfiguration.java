package com.LearnSpringSecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration //@Configuration is a class-level annotation indicating that an object is a source of bean definitions. @Configuration classes declare beans through @Bean -annotated methods. Calls to @Bean methods on @Configuration classes can also be used to define inter-bean dependencies.
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired
    private MyUserDetailService myUserDetailService;

    @Bean //One of the most important annotations in spring is the @Bean annotation which is applied on a method to specify that it returns a bean to be managed by Spring context. Spring Bean annotation is usually declared in Configuration classes methods. This annotation is also a part of the spring core framework.
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable) // refer registration controller class for explanation
                .authorizeHttpRequests(registry -> {
                    registry.requestMatchers("/home", "/register/**").permitAll(); //to allow the homepage to accessible for every one, that can be done by requestMatchers method and permitAll() used to specify permit all peoples to visit the homepage
                    registry.requestMatchers("/admin/**").hasRole("ADMIN"); // this allows only admins, any view starting with "/admin/**" can only be accessed by who has the role "ADMIN", we can assign the ADMIN Role through Database
                    registry.requestMatchers("/user/**").hasRole("USER"); // this allows only users, any view starting with "/user/**" can only 
                    registry.anyRequest().authenticated(); // if there is any other url that is not specified here that requires authentication, that is the meaning of this line
                })
                .formLogin(httpSecurityFormLoginConfigurer -> {
                    httpSecurityFormLoginConfigurer
                            .loginPage("/login")
                            .successHandler(new AuthenticationSuccessHandler())
                            .permitAll();
                })
                .build(); //
    }

    //In memory user authentication , here did not create user roles in db we just configure them in line here and try to login with it
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails normalUser = User.builder() //first user
//                .username("Navaneeth")
//                .password("$2a$12$mmCJBIypNRYfFL75kaspNu6AJHl4bf/PZa9MBsCjHcsm1fVWQ.rOi") //giving password as a plain text is a bad approach, we can easily reverse engineered it, so it is always recommended to password encoder to secure the password
//                .roles("USER")
//                .build();
//
//        UserDetails adminUser = User.builder()
//                .username("admin")
//                .password("$2a$12$QbanEFk141g6d2dsDI1SpeteU.e/tYKRJC5eyV/8BBesBD/LiH34K") //giving password as a plain text is a bad approach, we can easily reverse engineered it, so it is always recommended to password encoder to secure the password
//                .roles("ADMIN","USER") // admin can access everything so specify Both roles USER and ADMIN
//                .build();
//
//        return new InMemoryUserDetailsManager(normalUser,adminUser);
//    }

    // to secure password using password encoder
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }   //using password encoder we encrypt the password to provide security and also that can't be reverse engineered

    @Bean
    public UserDetailsService userDetailsService(){
        return myUserDetailService;
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(myUserDetailService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    } /* we need to tell the user details service or the authentication provider that what kind of authentication we are going to use
      inorder to do that we have Authentication provider
      DaoAuthenticationProvider - this is also from the spring boot security core . This is for explicitly created for loading users from the db or any other data access layer and use it for authentication
      here wee need to set 2 things user details service and password encoder we are using to encode the password so we set the user, then we have to simply return the provider */



}
