package com.hetongxue.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @Description: SpringWeb配置类
 * @ClassNmae: SpringWebConfiguration
 * @Author: 何同学
 * @DateTime: 2022-08-01 14:01
 */
@Configuration
@EnableWebMvc
public class SpringWebConfiguration implements WebMvcConfigurer {

    private final String[] classpathResourceLocations = {
            "classpath:/META-INF/resources/", "classpath:/resources/",
            "classpath:/static/", "classpath:/public/", "classpath:/META-INF/resources/webjars/"};

    /**
     * 资源处理器
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**")
                .addResourceLocations(classpathResourceLocations);
        registry.addResourceHandler("doc.html")
                .addResourceLocations("classpath:/META-INF/resources/");
        registry.addResourceHandler("swagger-ui.html")
                .addResourceLocations("classpath:/META-INF/resources/");
        registry.addResourceHandler("/webjars/**")
                .addResourceLocations("classpath:/META-INF/resources/webjars/");
    }

    /**
     * 跨域配置
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")// 添加映射路径
                .allowedHeaders("*")// 放行哪些原始请求头部信息
                .exposedHeaders("*")// 暴露哪些头部信息
                .allowedMethods("POST", "GET", "PUT", "OPTIONS", "DELETE", "TRACE", "HEAD", "PATCH")// 放行哪些请求方式
                .allowCredentials(true)// 是否发送 Cookie
                .maxAge(3600L)// 最大时间
                .exposedHeaders("authorization")
                .allowedOriginPatterns("*");
    }

}