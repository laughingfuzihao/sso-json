package com.gwssi.ssojson.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import java.util.Enumeration;

/**
 * @author Fu zihao
 * @version 1.0
 * @Description:
 * @date 20202020/8/12 10:05
 */
@RestController
public class LoginController {
    private Enumeration<String> AttributeNames;

    @GetMapping("/success")
    public String success(HttpSession session) {
        AttributeNames = session.getAttributeNames();
        AttributeNames = session.getAttributeNames();
        String spring_security_context = session.getAttribute("SPRING_SECURITY_CONTEXT").toString();
        return "登陆成功" + session.getAttributeNames();
    }
}
