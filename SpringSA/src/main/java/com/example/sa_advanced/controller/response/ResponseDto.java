package com.example.sa_advanced.controller.response;
import com.example.sa_advanced.domain.Error;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ResponseDto<T> {
  private boolean success;
  private T data;
  private Error error;

  public static <T> ResponseDto<T> success(T data) { // 제네릭스
    return new ResponseDto<>(true, data, null);
  }

  public static <T> ResponseDto<T> fail(String code, String message) { // 제네릭스
    return new ResponseDto<>(false, null, new Error(code, message));
  }

}
