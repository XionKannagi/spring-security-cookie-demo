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
