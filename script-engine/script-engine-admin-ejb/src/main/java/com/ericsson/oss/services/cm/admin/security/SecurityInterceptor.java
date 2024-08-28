/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.admin.security;

import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import java.util.Optional;

import static com.ericsson.oss.services.cm.admin.security.AccessControl.APP_PARAM_VIEW;
import static java.util.Objects.isNull;
import static java.util.Optional.ofNullable;

@Secure
@Interceptor
public class SecurityInterceptor {

    @Inject
    private AdminAuthorizer authorizer;

    @AroundInvoke
    @SuppressWarnings("PMD.SignatureDeclareThrowsException")
    public Object around(final InvocationContext context) throws Exception {
        final AccessControl accessControl = getSecurityAnnotation(context)
            .map(Secure::accessControl)
            .orElse(APP_PARAM_VIEW);
        authorizer.authorize(accessControl);
        return context.proceed();
    }

    private Optional<Secure> getSecurityAnnotation(final InvocationContext context) {
        Secure annotation = context.getMethod().getAnnotation(Secure.class);
        if (isNull(annotation)) {
            annotation = context.getTarget().getClass().getAnnotation(Secure.class);
        }
        return ofNullable(annotation);
    }
}