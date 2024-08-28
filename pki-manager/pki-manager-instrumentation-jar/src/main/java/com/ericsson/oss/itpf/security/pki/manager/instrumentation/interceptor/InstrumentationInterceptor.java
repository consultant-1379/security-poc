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
package com.ericsson.oss.itpf.security.pki.manager.instrumentation.interceptor;

import java.lang.reflect.Method;

import javax.inject.Inject;
import javax.interceptor.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.annotation.InstrumentationAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.InstrumentationService;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.InstrumentationServiceFactory;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;

/**
 * The interceptor to capture the performance metrics
 * 
 * @author 1254288
 * 
 */
@InstrumentationAnnotation
@Interceptor
public class InstrumentationInterceptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstrumentationInterceptor.class);

    @Inject
    InstrumentationServiceFactory instrumentationServiceFactory;

    /**
     * This method is called to process the @InstrumentationAnnotation annotation.
     * 
     * This invokes the instrumentation service returned by the InstrumentationServiceFactory based on the MetriGroup
     * 
     * @param invocationContext
     *            the InvocationContext instance passed by the container
     * @return the invocation result of the intercepted method
     * @throws Exception
     *             when any exception arises during invocation
     */
    @SuppressWarnings("PMD.SignatureDeclareThrowsException")
    @AroundInvoke
    public Object intercept(final InvocationContext invocationContext) throws Exception {
        final long start = System.currentTimeMillis();

        InstrumentationService pkiManagerInstrumentationService = null;
        MetricGroup metricGroup = MetricGroup.UNKNOWN;
        MetricType metricType = MetricType.UNKNOWN;

        final Method interceptedMethod = invocationContext.getMethod();

        LOGGER.debug("Found method annotated with @PKIManagerInstrumentationAnnotation annotation for method: {}", interceptedMethod);

        if (interceptedMethod != null && interceptedMethod.isAnnotationPresent(InstrumentationAnnotation.class)) {
            final InstrumentationAnnotation pkiManagerInstrumentationAnnotation = interceptedMethod.getAnnotation(InstrumentationAnnotation.class);
            metricGroup = pkiManagerInstrumentationAnnotation.metricGroup();
            metricType = pkiManagerInstrumentationAnnotation.metricType();

            pkiManagerInstrumentationService = instrumentationServiceFactory.getInstrumentationService(metricGroup);
            pkiManagerInstrumentationService.setMethodInvocations(metricType);
            LOGGER.debug("Increased number of invocations for metric group {}, metric type {}", metricGroup, metricType);
        }

        try {
            final Object result = invocationContext.proceed();
            return result;
        } catch (final Exception exception) {
            LOGGER.debug("Increased number of failures for metric group {}, metric type {}", metricGroup, metricType);

            if (pkiManagerInstrumentationService != null) {
                pkiManagerInstrumentationService.setMethodFailures(metricType);
            }
            throw exception;
        } finally {
            LOGGER.debug("Exposed execution time of {}ms for metric group, metric type  {}", System.currentTimeMillis() - start, metricGroup, metricType);

            if (pkiManagerInstrumentationService != null) {
                pkiManagerInstrumentationService.setExecutionTimeTotalMillis(metricType, System.currentTimeMillis() - start);
            }
        }
    }
}