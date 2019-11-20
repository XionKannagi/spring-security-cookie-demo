# Spring Security サンプルの説明
このサンプルはSpring Securityを使用してCookieの情報を元に認証を行うサンプルです。


## 1. directory構成

この中の**securiy**配下にSpring Securityに必要なクラスが全て入っています。　　
```
＄tree ./security-demo/src/

├── main
│   ├── java
│   │   └── com
│   │       └── example
│   │           └── securitydemo
│   │               ├── SecurityDemoApplication.java
│   │               ├── application
│   │               │   └── controller
│   │               │       └── ApiController.java
│   │               └── security
│   │                   ├── configuration
│   │                   │   └── SecurityConfiguration.java
│   │                   ├── entrypoint
│   │                   │   └── AuthenticationEntryPointImpl.java
│   │                   └── filter
│   │                       └── CookieFilter.java
│   └── resources
│       ├── application.yml
│       ├── static
│       └── templates
:
:
```

## 2. 動作の説明
Spring Securityの基本的な動作はホストがリクエストを受け付けると、  
Controllerクラスへ処理が入る直前に割り込み処理として自動でセキュリティが介入し  
認証処理を行ってくれます。  
上記によってセキュリティー層という範囲で柔軟な認証処理ができます。  

  <img width="1000" alt="Spring-Security.png" src="https://raw.githubusercontent.com/XionKannagi/spring-security-cookie-demo/master/Spring-Security.png">

### 2-1. Security関連クラスの説明
 #### 1. Configurationクラス
 
 SecurityConfiguration.java
 ```SecurityConfiguration.java
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

    http
        // AUTHORIZE
        .antMatcher("/v1/api/**")
          .authorizeRequests()
            .antMatchers("/v1/api/no-auth")
              .permitAll()
            .antMatchers("/v1/api/auth")
              .access("isAuthenticated() and hasRole('APP_USER')")
            .antRequest()
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

```

この中で重要になるのがオーバーライドメソッドのconfigureになります。  
このメソッドではセキュリティ上重要となるの以下３つを定義しています。
 1. アクセス制限  
 2. 認証失敗時の処理  
 3. 認証フィルターの追加  

```java: configure
@Override
  protected void configure(HttpSecurity http) throws Exception {

    http
        // AUTHORIZE
        .antMatcher("/v1/api/**")
          .authorizeRequests()
            .mvcMatchers("/v1/api/no-auth")
              .permitAll()
            .mvcMatchers("/v1/api/auth")
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
        // AUTHORIZE FILTER
        .addFilter(cookieFilter())
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    ;
  }
```

 #### 1. アクセス制限  
 Spring Securityのアクセス制限は以下の部分で行ってます。

```java: access limitation
        // AUTHORIZE
        .antMatcher("/v1/api/**")
          .authorizeRequests()
            .antMatchers("/v1/api/no-auth")
              .permitAll()
            .antMatchers("/v1/api/auth")
              .access("isAuthenticated() and hasRole('APP_USER')")
            .anyRequest()
              .authenticated()
```
上の部分で自リソースへのパスベースのアクセス制限を行っています。  
詳細に関しては割愛しますが以下でで実際のアクセス制限をしてます.  

- /v1/api/no-auth => 全リクエストへのアクセス許可  
- /v1/api/auth => APP_USERロールを持つユーザーのみアクセス許可  
**※APP_USERロールについては後述.**

 ##### 2. 認証失敗時の処理
 認証失敗時の処理はこの部分で行われています.  
 認証に失敗すると後述のauthenticationEntryPoint()へ処理が引き継がれます。
```java: exception handler
        // EXCEPTION
          .exceptionHandling()
            .authenticationEntryPoint(authenticationEntryPoint())
            .accessDeniedHandler(accessDeniedHandler())
```

 ##### 3. 認証フィルターの追加
 今回のCookie検証はこの部分でセキュリティフィルターとして追加されています。  
 サンプルでは一つのフィルターのみですが、ここに複数のフィルターを追加することで多重のフィルタリングが可能になります。
 ```java: Add Cookie Filter
        // AUTHORIZE FILTER
        .addFilter(cookieFilter())
```

 #### 2. EntryPoint実装クラス
 EntryPointは認証失敗時の処理を記述するクラスになります。  
 今回は認証失敗時にgoogleのページへリダイレクトする設定にしました。  
 ここは本来loginページなどへリダイレクトすることが多いと思います。  
 
 
 AuthenticationEntryPointImpl.java
 ```java: AuthenticationEntryPointImpl.java
package com.example.securitydemo.security.entrypoint;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

/**
 * 認証失敗時のエントリーポイント実装クラス.
 *
 * @author snail
 * @version 0.0.1
 */
@Slf4j
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {

  private static final Logger logger = LoggerFactory.getLogger(AuthenticationEntryPointImpl.class);


  /**
   * 認証失敗時の処理をするメソッド.
   *
   * @param request
   * @param response
   * @param exception
   * @throws IOException
   */
  @Override
  public void commence(HttpServletRequest request,
                       HttpServletResponse response,
                       AuthenticationException exception) throws IOException {
    if (response.isCommitted()) {
      logger.info("Response has already been committed.");
      return;
    }
    dump(exception);

    /* Todo: 認証失敗時のリダイレクト先を指定 */
    response.sendRedirect("https://www.google.co.jp/");

    /* 本来はこのような指定でステータスコードを返却する */
    // response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
  }

  /**
   * エラーダンプメソッド.
   *
   * @param e
   */
  private void dump(AuthenticationException e) {
    if (e instanceof BadCredentialsException) {
      logger.debug("BadCredentialsException : {}", e.getMessage());
    } else if (e instanceof LockedException) {
      logger.debug("LockedException : {}", e.getMessage());
    } else if (e instanceof DisabledException) {
      logger.debug("DisabledException : {}", e.getMessage());
    } else if (e instanceof AccountExpiredException) {
      logger.debug("AccountExpiredException : {}", e.getMessage());
    } else if (e instanceof CredentialsExpiredException) {
      logger.debug("CredentialsExpiredException : {}", e.getMessage());
    } else if (e instanceof SessionAuthenticationException) {
      logger.debug("SessionAuthenticationException : {}", e.getMessage());
    } else {
      logger.debug("AuthenticationException : {}", e.getMessage());
    }
  }
}

```
 
 #### 3. フィルタクラス
 フィルタークラスでは実際の認証におけるフィルタリング処理を記述しています。  
 このクラスでポイントとなるのは ***doFilter()*** メソッドになります。  
  ***doFilter()*** メソッド内にてリクエストの検証を行っています。  
  今回はCookieの内容をリクエストから取り出し検証しています。  
  検証に成功するとリクエストに対して任意の ***Principle(Object)*** と  
  ***Role*** を与えます。  
  この時与えたRoleがConfigureにて制限の基準になります。  
  
 CookieFilter.java
 ```java: CookieFilter.java
 package com.example.securitydemo.security.filter;
 
 import java.io.IOException;
 import java.util.Optional;
 import javax.servlet.FilterChain;
 import javax.servlet.ServletException;
 import javax.servlet.ServletRequest;
 import javax.servlet.ServletResponse;
 import javax.servlet.http.Cookie;
 import javax.servlet.http.HttpServletRequest;
 import lombok.extern.slf4j.Slf4j;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
 import org.springframework.security.core.authority.AuthorityUtils;
 import org.springframework.security.core.context.SecurityContextHolder;
 import org.springframework.security.web.context.SecurityContextRepository;
 import org.springframework.security.web.session.SessionManagementFilter;
 
 
 /**
  * リクエストのCookieを検証およびフィルタリングクラス.
  *
  * @author snail
  * @version 0.0.1
  */
 @Slf4j
 public class CookieFilter extends SessionManagementFilter {
 
   private static final Logger logger = LoggerFactory.getLogger(CookieFilter.class);
 
 
   public CookieFilter (SecurityContextRepository securityContextRepository) {
     super(securityContextRepository);
   }
 
   /**
    * フィルターメソッド.
    *
    * @param request
    * @param response
    * @param chain
    * @throws IOException
    * @throws ServletException
    */
   @Override
   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
       throws IOException, ServletException {
 
     if(verifyCookie(request)){
       authentication();
     }
 
     chain.doFilter(request, response);
   }
 
   /**
    * Cookie検証メソッド.
    *
    * @param request
    * @return Cookie検証の合否
    */
   private boolean verifyCookie(ServletRequest request) {
 
     Optional<Cookie[]> cookies = Optional.ofNullable(((HttpServletRequest) request).getCookies());
 
     if(cookies.isPresent()){
       for (Cookie cookie : cookies.get()) {
         logger.info(String.format("Cookies: %s=%s", cookie.getName(), cookie.getValue()));
 
         if (cookie.getName().equals("login_user")) {
           /* Todo: 認証APIを呼び出す処理を実装する. */
 
           return true;
         }
       }
     }
     return false;
   }
 
   /**
    * 認証およびロール付与を処理するメソッド.
    *
    * @param
    * @return
    */
   private void authentication() {
     SecurityContextHolder.getContext().setAuthentication(
         new UsernamePasswordAuthenticationToken(
             "app_user",
             null,
             AuthorityUtils.createAuthorityList("ROLE_APP_USER")));
   }
 
 }
```




