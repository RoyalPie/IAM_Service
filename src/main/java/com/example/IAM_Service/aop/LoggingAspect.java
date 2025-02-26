package com.example.IAM_Service.aop;

import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Aspect
@Component
public class LoggingAspect {
    private static final Logger logger = LoggerFactory.getLogger(LoggingAspect.class);

    @Around("execution(* com.example.IAM_Service.controller..*(..))")
    public Object logRequestResponse(ProceedingJoinPoint joinPoint) throws Throwable {
        HttpServletRequest request =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        logger.info("Request: {} {}", request.getMethod(), request.getRequestURI());

        Object result;
        try {
            result = joinPoint.proceed();
            logger.info("Response: {}", result);
        } catch (Exception e) {
            logger.error("Exception: {}", e.getMessage());
            throw e;
        }

        return result;
    }
}
