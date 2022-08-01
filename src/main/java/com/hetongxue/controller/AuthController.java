package com.hetongxue.controller;

import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.util.SaResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Description: 安全模块
 * @ClassNmae: AuthController
 * @Author: 何同学
 * @DateTime: 2022-08-01 13:55
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    // 这里省去数据库校验 直接使用固定数据校验
    private final static Long ID = 10001L;
    private final static String USERNAME = "admin";
    private final static String PASSWORD = "123456";

    @PostMapping("/login")
    public SaResult login(String username, String password) {
        // 1.校验用户名和密码
        if (USERNAME.equals(username) && PASSWORD.equals(password)) {
            // 根据ID进行登录
            StpUtil.login(ID);
            return SaResult.ok().setMsg("登陆成功");
        }
        return SaResult.error().setMsg("登陆失败");
    }

    @GetMapping("/logout")
    public SaResult logout() {
        StpUtil.logout();
        return SaResult.ok().setMsg("注销成功");
    }

    @GetMapping("/checkLogin")
    public SaResult checkLogin() {
        StpUtil.checkLogin();
        return SaResult.ok().setMsg("已登陆");
    }

    @GetMapping("/tokenInfo")
    public SaResult tokenInfo() {
        return SaResult.ok().setData(StpUtil.getTokenInfo());
    }
}