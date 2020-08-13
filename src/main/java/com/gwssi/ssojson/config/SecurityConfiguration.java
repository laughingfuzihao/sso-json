package com.gwssi.ssojson.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author Fu zihao
 * @version 1.0
 * @Description:
 * @date 20202020/8/12 9:58
 */
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("laughing")
                .password(new BCryptPasswordEncoder().encode("123456"))
                .roles("admin");

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //  web.ignoring 不进行拦截（一般对于静态文件）
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**", "/favicon.ico");
    }

    //定义登陆成功返回信息
    private class AjaxAuthSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            response.setContentType("application/json;charset=utf-8");
            PrintWriter out = response.getWriter();
            // Authentication 参数则保存了我们刚刚登录成功的用户信息。
            Object principal = authentication.getPrincipal();
            out.write(new ObjectMapper().writeValueAsString(principal));
            /*out.write("{\"status\":\"ok\",\"msg\":\"登录成功\"}");*/
            out.flush();
            out.close();
        }
    }


    //定义登陆失败返回信息
    private class AjaxAuthFailureHandler extends SimpleUrlAuthenticationFailureHandler {
        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse resp, AuthenticationException e) throws IOException, ServletException {
            resp.setContentType("application/json;charset=utf-8");
            PrintWriter out = resp.getWriter();
            resp.setStatus(HttpStatus.UNAUTHORIZED.value());
            if (e instanceof LockedException) {
                out.write("{\"status\":\"error\",\"msg\":\"账户被锁定，请联系管理员!\"}");
            } else if (e instanceof CredentialsExpiredException) {
                out.write("{\"status\":\"error\",\"msg\":\"密码过期，请联系管理员!\"}");
            } else if (e instanceof AccountExpiredException) {
                out.write("{\"status\":\"error\",\"msg\":\"账户过期，请联系管理员!\"}");
            } else if (e instanceof DisabledException) {
                out.write("{\"status\":\"error\",\"msg\":\"账户被禁用，请联系管理员!\"}");
            } else if (e instanceof BadCredentialsException) {
                out.write("{\"status\":\"error\",\"msg\":\"用户名或者密码输入错误，请重新输入!\"}");
            }
            out.flush();
            out.close();
        }
    }

    //未登录  用来解决匿名用户访问无权限资源时的异常
    public class UnauthorizedEntryPoint implements AuthenticationEntryPoint {
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
            response.setContentType("application/json;charset=utf-8");
            PrintWriter out = response.getWriter();
            out.write("{\"status\":\"error\",\"msg\":\"尚未登录，请先登录!\"}");
            out.flush();
            out.close();
        }
    }

    //定义登出成功返回信息
    private class AjaxLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                    Authentication authentication) throws IOException, ServletException {
            response.setContentType("application/json;charset=utf-8");
            PrintWriter out = response.getWriter();
            out.write("{\"status\":\"ok\",\"msg\":\"登出成功\"}");
            out.flush();
            out.close();
        }
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //
        http.authorizeRequests()
                // 用户访问权限
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")
                .successHandler(new AjaxAuthSuccessHandler())
                .failureHandler(new AjaxAuthFailureHandler())
                .permitAll()
                .and()
                .logout().logoutSuccessHandler(new AjaxLogoutSuccessHandler())
                .logoutUrl("/logout")
                .and()
                .csrf().disable()
                // 未登录验证
                .exceptionHandling().authenticationEntryPoint(new UnauthorizedEntryPoint());
    }


}
