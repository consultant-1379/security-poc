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
package com.ericsson.oss.itpf.security.pki.manager.instrumentation.annotation;

import java.lang.annotation.*;

import javax.enterprise.util.Nonbinding;
import javax.interceptor.InterceptorBinding;

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;

/**
 * Annotate a method with this type, if its performance metrics has to be captured.
 * 
 * @author 1254288
 * 
 */
@Inherited
@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.METHOD, ElementType.TYPE })
public @interface InstrumentationAnnotation {

    @Nonbinding
    MetricGroup metricGroup() default MetricGroup.UNKNOWN;

    @Nonbinding
    MetricType metricType() default MetricType.UNKNOWN;
}
