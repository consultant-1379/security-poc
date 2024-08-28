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
package com.ericsson.oss.itpf.security.pki.cdps.notification.instrumentation;

import java.util.concurrent.atomic.AtomicInteger;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.instrument.annotation.InstrumentedBean;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.*;

@ApplicationScoped
@InstrumentedBean(displayName = "Daily Totals of publish & unpublish CRL(s)")
public class CRLInstrumentationBean {

    /**
     * Display names of performance metrics
     */
    public static final String PUBLISH_INVOCATIONS = "Number of CRL Publish Reuqests";
    public static final String PUBLISH_SUCCESSES = "Number of Successful CRL Publish Requests";

    public static final String UNPUBLISH_INVOCATIONS = "Number of CRL UnPublish Reuqests";
    public static final String UNPUBLISH_SUCCESSES = "Number of Successful CRL UnPublish Requests";

    /**
     * Variable declarations that capture performance metrics
     */
    private final AtomicInteger publishMethodInvocations = new AtomicInteger(0);
    private final AtomicInteger publishMethodSuccesses = new AtomicInteger(0);
    private final AtomicInteger unPublishMethodInvocations = new AtomicInteger(0);
    private final AtomicInteger unPublishMethodSuccesses = new AtomicInteger(0);
    /**
     * @return the publishMethodInvocations
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = PUBLISH_INVOCATIONS)
    public int getPublishMethodInvocations() {
        return publishMethodInvocations.get();
    }
    /**
     * @param publishMethodInvocations the publishMethodInvocations to set
     */
    public void setPublishMethodInvocations() {
        publishMethodInvocations.incrementAndGet();
    }
    /**
     * @return the unPublishMethodInvocations
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = UNPUBLISH_INVOCATIONS)
    public int getUnPublishMethodInvocations() {
        return unPublishMethodInvocations.get();
    }
    /**
     * @param unPublishMethodInvocations the unPublishMethodInvocations to set
     */
    public void setUnPublishMethodInvocations() {
        unPublishMethodInvocations.incrementAndGet();
    }
    /**
     * @return the publishMethodSuccesses
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = PUBLISH_SUCCESSES)
    public int getPublishMethodSuccess() {
        return publishMethodSuccesses.get();
    }
    /**
     * @param publishMethodSuccesses the publishMethodSuccesses to set
     */
    public void setPublishMethodSuccess() {
        publishMethodSuccesses.incrementAndGet();
    }
    /**
     * @return the unPublishMethodSuccesses
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = UNPUBLISH_SUCCESSES)
    public int getUnPublishMethodSuccess() {
        return unPublishMethodSuccesses.get();
    }
    /**
     * @param unPublishMethodSuccesses the unPublishMethodSuccesses to set
     */
    public void setUnPublishMethodSuccess() {
        unPublishMethodSuccesses.incrementAndGet();
    }

    
}
