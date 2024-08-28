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
package com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.metrics;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.instrument.annotation.*;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Category;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.CollectionType;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Interval;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Units;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Visibility;

/**
 * <p>
 * Instrumentation bean for capturing the performance metrics of following CRL Management APIs.
 * <ul>
 * <li>generateCRL()</li>
 * </ul>
 * 
 * It captures the following performance metrics:
 * <ul>
 * <li>methodFailures</li>
 * <li>methodInvocations</li>
 * <li>executionTimeTotalMillis</li>
 * </ul>
 * 
 * </p>
 * 
 * @author 1254288
 * 
 */
@ApplicationScoped
@InstrumentedBean(displayName = "CRL Management Daily Totals")
public class CRLManagementInstrumentationBean {

    /**
     * Display names of performance metrics
     */
    public static final String DESC_GENERATE_INVOCATIONS = "Number of invocations on generate method.";
    public static final String DESC_GENERATE_FAILURES = "Number of times generate method failed.";
    public static final String DESC_GENERATE_EXEC_TIME_TOTAL = "Total execution time of generate method (ms).";

    /**
     * Variable declarations that capture performance metrics
     */
    private final AtomicInteger generateMethodInvocations = new AtomicInteger(0);
    private final AtomicInteger generateMethodFailures = new AtomicInteger(0);
    private final AtomicLong generateExecutionTimeTotalMillis = new AtomicLong(0);

    /**
     * Returns no. of times generate method was invoked
     * 
     * @return the count
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_GENERATE_INVOCATIONS)
    public int getGenerateMethodInvocations() {
        return generateMethodInvocations.get();
    }

    /**
     * Increases the no. of invocations on generate method by 1
     * 
     */
    public void setGenerateMethodInvocations() {
        generateMethodInvocations.incrementAndGet();
    }

    /**
     * Returns no. of times generate method has failed
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_GENERATE_FAILURES)
    public int getGenerateMethodFailures() {
        return generateMethodFailures.get();
    }

    /**
     * Increases the no. of failures of generate method by 1
     * 
     */
    public void setGenerateMethodFailures() {
        generateMethodFailures.incrementAndGet();
    }

    /**
     * Returns the total execution time of generate method in milli seconds
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.MILLISECONDS, visibility = Visibility.INTERNAL, displayName = DESC_GENERATE_EXEC_TIME_TOTAL)
    public long getGenerateExecutionTimeTotalMillis() {
        return generateExecutionTimeTotalMillis.get();
    }

    /**
     * Increases total execution time of generate method by the value given in execution time
     * 
     */
    public void setGenerateExecutionTimeTotalMillis(final long executionTime) {
        generateExecutionTimeTotalMillis.addAndGet(executionTime);
    }
}
