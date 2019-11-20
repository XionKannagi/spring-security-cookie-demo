package com.example.securitydemo.application.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * コントローラークラス.
 *
 * @author regpon
 * @version 0.1.0
 */
@RestController
@RequestMapping("/v1/api")
@RequiredArgsConstructor
public class ApiController {

  /**
   * テスト用のエンドポイント(認証なし).
   *
   * @return メッセージ
   */
  @GetMapping("/no-auth")
  public String getApiWithoutAuth() {

    /* implement something */
    return "{\"message\": \"API Response!\", \"auth\": \"no\"}";
  }

  /**
   * テスト用のエンドポイント(認証あり).
   *
   * @return メッセージ
   */
  @GetMapping("/auth")
  public String getApiWithAuth() {

    /* implement something */
    return "{\"message\": \"API Response!\", \"auth\": \"yes\"}";
  }
}
