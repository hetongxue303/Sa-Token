package com.hetongxue.controller;

import cn.dev33.satoken.annotation.*;
import cn.dev33.satoken.stp.SaLoginModel;
import cn.dev33.satoken.stp.SaTokenInfo;
import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.util.SaResult;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;

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
    @Resource
    private HttpServletResponse response;

    @PostMapping("/login")
    public SaResult login(String username, String password) {
        // 1.校验用户名和密码
        if (USERNAME.equals(username) && PASSWORD.equals(password)) {
            /**
             * 参数1：登录ID
             * 参数2：记住我
             * 参数3：指定token过期时间（单位：秒）
             */
//            StpUtil.login(ID, true, new SaLoginModel().setTimeout(60 * 60 * 24 * 7));
//            StpUtil.login(ID, new SaLoginModel().setTimeout(60 * 60 * 24 * 7));// 设置7天有效
            /**
             * 全参数设置
             */
            // 生成token对象
            SaTokenInfo tokenInfo = StpUtil.getTokenInfo();
            StpUtil.login(ID, new SaLoginModel()
                    .setDevice("phone")                  // 此次登录的客户端设备类型, 用于[同端互斥登录]时指定此次登录的设备类型
                    .setIsLastingCookie(true)            // 是否为持久Cookie（临时Cookie在浏览器关闭时会自动删除，持久Cookie在重新打开后依然存在）
                    .setTimeout(60 * 60 * 24 * 7)        // 指定此次登录token的有效期, 单位:秒 （如未指定，自动取全局配置的 timeout 值）
                    .setToken(tokenInfo.getTokenValue()) // 预定此次登录的生成的Token
            );
            // 设置token信息到响应头
            response.setHeader("authorization", tokenInfo.getTokenValue());
            return SaResult.ok().setMsg("登陆成功").setData(tokenInfo);
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