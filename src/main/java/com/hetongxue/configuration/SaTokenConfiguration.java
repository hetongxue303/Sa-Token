package com.hetongxue.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
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
//    @Override
//    public void addInterceptors(InterceptorRegistry registry) {
//        // 注册注解拦截器
//        registry.addInterceptor(new SaAnnotationInterceptor())
//                // 不需要鉴权的接口地址
//                .addPathPatterns("/**");
//    }


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


//    /****************方式1:此配置会覆盖yml中的配置******************/
//    @Bean
//    @Primary
//    public SaTokenConfig getSaTokenConfigPrimary() {
//        SaTokenConfig config = new SaTokenConfig();
//        config.setTokenName("satoken");             // token名称 (同时也是cookie名称)
//        config.setTimeout(30 * 24 * 60 * 60);       // token有效期，单位s 默认30天
//        config.setActivityTimeout(-1);              // token临时有效期 (指定时间内无操作就视为token过期) 单位: 秒
//        config.setIsConcurrent(true);               // 是否允许同一账号并发登录 (为true时允许一起登录, 为false时新登录挤掉旧登录)
//        config.setIsShare(true);                    // 在多人登录同一账号时，是否共用一个token (为true时所有登录共用一个token, 为false时每次登录新建一个token)
//        config.setTokenStyle("uuid");               // token风格
//        config.setIsLog(false);                     // 是否输出操作日志
//        return config;
//    }
//
//    /****************方式2:此配置会合并yml中的配置******************/
//    @Autowired
//    public void configSaToken(SaTokenConfig config) {
//        config.setTokenName("satoken");             // token名称 (同时也是cookie名称)
//        config.setTimeout(30 * 24 * 60 * 60);       // token有效期，单位s 默认30天
//        config.setActivityTimeout(-1);              // token临时有效期 (指定时间内无操作就视为token过期) 单位: 秒
//        config.setIsConcurrent(true);               // 是否允许同一账号并发登录 (为true时允许一起登录, 为false时新登录挤掉旧登录)
//        config.setIsShare(true);                    // 在多人登录同一账号时，是否共用一个token (为true时所有登录共用一个token, 为false时每次登录新建一个token)
//        config.setTokenStyle("uuid");               // token风格
//        config.setIsLog(false);
//    }
}