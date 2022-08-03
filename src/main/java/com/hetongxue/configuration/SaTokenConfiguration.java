package com.hetongxue.configuration;

import cn.dev33.satoken.interceptor.SaAnnotationInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @Description: SaToken配置类
 * @ClassNmae: SaTokenConfiguration
 * @Author: 何同学
 * @DateTime: 2022-08-02 16:49
 */
@Configuration
@EnableWebMvc
public class SaTokenConfiguration implements WebMvcConfigurer {
    // 放行白名单(除白名单内的接口 其余的都需要验证)
    private static final String[] WHITELIST = {"/auth/login"};

    /**
     * 注册注解拦截器 排除不需要注解鉴权的接口地址 (与登录拦截器无关)
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 注册注解拦截器
        registry.addInterceptor(new SaAnnotationInterceptor())
                // 不需要鉴权的接口地址
                .addPathPatterns("/**");
    }


    /**
     * 注册路由拦截器(只进行默认的登录校验功能)
     */
//    @Override
//    public void addInterceptors(InterceptorRegistry registry) {
//        registry.addInterceptor(new SaRouteInterceptor())
//                .addPathPatterns("/**")
//                // 白名单
//                .excludePathPatterns(WHITELIST);
//    }


    /**
     * 注册路由拦截器(自定义拦截规则)
     */
//    @Override
//    public void addInterceptors(InterceptorRegistry registry) {
//        registry.addInterceptor(new SaRouteInterceptor((req, res, handler) -> {
//            // 登录认证    拦截所有路由，并排除/user/doLogin 用于开放登录
//            SaRouter.match("/**", "/auth/login", r -> StpUtil.checkLogin());
//
//            // 角色认证    拦截以 test 开头的路由，必须具备 admin 角色或者 super-admin 角色才可以通过认证
//            SaRouter.match("/test/**", r -> StpUtil.checkRoleOr("admin", "super-admin"));
//
//            // 权限认证    不同模块认证不同权限
//            SaRouter.match("/test/**", r -> StpUtil.checkPermission("test"));
//            SaRouter.match("/admin/**", r -> StpUtil.checkPermission("admin"));
//            SaRouter.match("/super-admin/**", r -> StpUtil.checkPermission("super-admin"));
//        })).addPathPatterns("/**");
//    }

}