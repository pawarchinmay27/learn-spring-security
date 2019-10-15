package com.baeldung.lss.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@Configuration
public class LssSecurityConfig extends WebSecurityConfigurerAdapter {

    public LssSecurityConfig() {
        super();
    }


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception
    { // @formatter:off
            auth.
            inMemoryAuthentication().passwordEncoder(passwordEncoder()).
            withUser("user").password(passwordEncoder().encode("pass")).
                    roles("ADMIN");
    } // @formatter:on

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/delete/**").hasAuthority("ADMIN")
                .anyRequest().authenticated()
                //hasAuthority means the one who access the url shall have the role that of a admin  there can be multiple admins since it is a role
                .and()
                .formLogin().and()
                .httpBasic();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
