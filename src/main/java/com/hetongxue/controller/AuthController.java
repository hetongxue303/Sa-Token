package com.hetongxue.controller;

import cn.dev33.satoken.annotation.*;
import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.util.SaResult;
import org.springframework.web.bind.annotation.*;

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

    /**
     * 登录认证
     */
    @SaCheckLogin
    @GetMapping("/tokenInfo")
    public SaResult tokenInfo() {
        return SaResult.ok().setData(StpUtil.getTokenInfo());
    }

    /**
     * 权限认证
     */
    @SaCheckPermission("user:delete")
    @DeleteMapping("/delete")
    public SaResult delete() {
        return SaResult.ok("删除成功");
    }

    @SaCheckPermission("user:insert")
    @PostMapping("/insert")
    public SaResult insert() {
        return SaResult.ok("新增成功");
    }

    @SaCheckPermission("user:list")
    @GetMapping("/list")
    public SaResult list() {
        return SaResult.ok("查询列表成功");
    }

    @SaCheckPermission("user:update")
    @PutMapping("/update")
    public SaResult update() {
        return SaResult.ok("更新成功");
    }

    /**
     * 由于没有user:other权限 此时访问会提示无权限
     */
    @SaCheckPermission("user:other")
    @GetMapping("/other")
    public SaResult other() {
        return SaResult.ok("其他操作");
    }

    /**
     * 角色认证
     */
    @SaCheckRole("admin")
    @GetMapping("/isRole")
    public SaResult isRole() {
        return SaResult.ok("角色认证通过");
    }

    /**
     * 二级认证
     */
    @SaCheckSafe
    @GetMapping("/doubleCheck")
    public SaResult doubleCheck() {
        return SaResult.ok("二级验证通过");
    }

    /**
     * Http Basic 认证
     */
    @SaCheckBasic(account = "sa:admin")
    @GetMapping("/httpBasic")
    public SaResult httpBasic() {
        return SaResult.ok("httpBasic验证通过");
    }

}