/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.exception.log.interceptor;

import java.lang.reflect.Method;
import java.util.Arrays;

import javax.interceptor.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;

@ErrorLogAnnotation
@Interceptor
public class ErrorLogInterceptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(ErrorLogInterceptor.class);

    @SuppressWarnings("PMD.SignatureDeclareThrowsException")
    @AroundInvoke
    public Object intercept(final InvocationContext invocationContext) throws Exception {

        try {
            return invocationContext.proceed();
        } catch (final Exception exception) {
            LOGGER.error("The method : {} with parameters {}, failed to execute. Caused due to : {}", getRequestName(invocationContext), Arrays.deepToString(invocationContext.getParameters()),
                    exception.getMessage());
            throw exception;
        }
    }

    private String getRequestName(final InvocationContext invocationContext) {
        final Method method = invocationContext.getMethod();
        final String requestName = method.getDeclaringClass().getSimpleName() + "->" + method.getName();

        return requestName;
    }
}
