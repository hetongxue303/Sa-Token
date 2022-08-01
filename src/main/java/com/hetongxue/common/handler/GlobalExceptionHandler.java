package com.hetongxue.common.handler;

import cn.dev33.satoken.util.SaResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @Description: 全局异常捕获
 * @ClassNmae: GlobalExceptionHandler
 * @Author: 何同学
 * @DateTime: 2022-08-01 13:58
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @Resource
    private HttpServletRequest request;
    @Resource
    private HttpServletResponse response;

    /**
     * 全局异常拦截
     */
    @ExceptionHandler(Exception.class)
    public SaResult exception(Exception e) {
        e.printStackTrace();
        return SaResult.error(e.getMessage());
    }

}