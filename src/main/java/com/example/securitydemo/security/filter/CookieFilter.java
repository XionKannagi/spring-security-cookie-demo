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
