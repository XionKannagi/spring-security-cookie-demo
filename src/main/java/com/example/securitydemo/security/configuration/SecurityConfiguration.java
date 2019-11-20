package com.example.securitydemo.security.configuration;

import com.example.securitydemo.security.entrypoint.AuthenticationEntryPointImpl;
import com.example.securitydemo.security.filter.CookieFilter;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.session.SessionManagementFilter;


/**
 * セキュリティ設定を行うクラス.
 *
 * @author snail
 * @version 0.0.1
 */
@ComponentScan
@EnableWebSecurity
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {


  @Override
  protected void configure(HttpSecurity http) throws Exception {

    // @formatter:off
    http
        // AUTHORIZE
        .antMatcher("/v1/api/**")
          .authorizeRequests()
            .antMatchers("/v1/api/no-auth")
              .permitAll()
            .antMatchers("/v1/api/auth")
              .access("isAuthenticated() and hasRole('APP_USER')")
            .anyRequest()
              .authenticated()
        .and()
        // EXCEPTION
          .exceptionHandling()
            .authenticationEntryPoint(authenticationEntryPoint())
            .accessDeniedHandler(accessDeniedHandler())
        .and()
        // LOGOUT
        .logout()
          .logoutUrl("/api/v1/account/logout")
          .logoutSuccessHandler(logoutSuccessHandler())
          .deleteCookies("login_user")
        .and()
        // CSRF
          .csrf()
          .disable()
        // AUTHORIZE
        .addFilter(cookieFilter())
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    ;
    // @formatter:on
  }


  AuthenticationEntryPoint authenticationEntryPoint() {
    return new AuthenticationEntryPointImpl();
  }

  AccessDeniedHandler accessDeniedHandler() {
    return new AccessDeniedHandlerImpl();
  }


  SessionManagementFilter cookieFilter() {
    return new CookieFilter( new HttpSessionSecurityContextRepository() );
  }

  LogoutSuccessHandler logoutSuccessHandler() {
    return new HttpStatusReturningLogoutSuccessHandler();
  }
}

