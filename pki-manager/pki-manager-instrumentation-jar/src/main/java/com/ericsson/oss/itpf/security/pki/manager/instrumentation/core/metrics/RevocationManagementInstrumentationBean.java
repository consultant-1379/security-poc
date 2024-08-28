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
 * Instrumentation bean for capturing the performance metrics of following Revocation Management APIs.
 * <ul>
 * <li>revokeCAEntityCertificates()
 * <li>
 * <li>revokeEntityCertificates()
 * <li>
 * <li>revokeCertificateByDN()
 * <li>
 * <li>revokeCertificateByIssuerName()
 * <li>
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
@InstrumentedBean(displayName = "Revocation Management Daily Totals")
public class RevocationManagementInstrumentationBean {

    /**
     * Display names of performance metrics
     */
    public static final String DESC_REVOKE_INVOCATIONS = "Number of invocations on revoke method.";
    public static final String DESC_REVOKE_FAILURES = "Number of times revoke method failed.";
    public static final String DESC_REVOKE_EXEC_TIME_TOTAL = "Total execution time of revoke method (ms).";

    /**
     * Variable declarations that capture performance metrics
     */
    private final AtomicInteger revokeMethodInvocations = new AtomicInteger(0);
    private final AtomicInteger revokeMethodFailures = new AtomicInteger(0);
    private final AtomicLong revokeExecutionTimeTotalMillis = new AtomicLong(0);

    /**
     * Returns no. of times revoke method was invoked
     * 
     * @return the count
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_REVOKE_INVOCATIONS)
    public int getRevokeMethodInvocations() {
        return revokeMethodInvocations.get();
    }

    /**
     * Increases the no. of invocations on revoke method by 1
     * 
     */
    public void setRevokeMethodInvocations() {
        revokeMethodInvocations.incrementAndGet();
    }

    /**
     * Returns no. of times revoke method has failed
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_REVOKE_FAILURES)
    public int getRevokeMethodFailures() {
        return revokeMethodFailures.get();
    }

    /**
     * Increases the no. of failures of revoke method by 1
     * 
     */
    public void setRevokeMethodFailures() {
        revokeMethodFailures.incrementAndGet();
    }

    /**
     * Returns the total execution time of revoke method in milli seconds
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.MILLISECONDS, visibility = Visibility.INTERNAL, displayName = DESC_REVOKE_EXEC_TIME_TOTAL)
    public long getRevokeExecutionTimeTotalMillis() {
        return revokeExecutionTimeTotalMillis.get();
    }

    /**
     * Increases total execution time of revoke method by the value given in execution time
     * 
     * @param executionTime
     *            time taken(in milli seconds) by the current run of revoke method
     */
    public void setRevokeExecutionTimeTotalMillis(final long executionTime) {
        revokeExecutionTimeTotalMillis.addAndGet(executionTime);
    }
}
