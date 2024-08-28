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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.instrumentation;

import java.util.concurrent.atomic.AtomicInteger;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.instrument.annotation.InstrumentedBean;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.*;

/**
 * Instrumentation bean for capturing the performance metrics of successful/unsuccessful invocations
 * for publish/unpublish certificate invocation to TDPS
 * 
 */
@ApplicationScoped
@InstrumentedBean(displayName = "Instrumentation for publish and unpublish Certificates to TDPS")
public class TDPSInstrumentationBean {

    /**
     * Display names of performance metrics
     */
    private static final String PUBLISH_INVOCATIONS = "Number of publish invocations";
    private static final String PUBLISH_FAILURES = "Number of failed publish invocations";

    private static final String UNPUBLISH_INVOCATIONS = "Number of unpublish invocations";
    private static final String UNPUBLISH_FAILURES = "Number of failed unpublish invocations";

    /**
     * Variable declarations that capture performance metrics
     */
    private final AtomicInteger publishInvocations = new AtomicInteger(0);
    private final AtomicInteger publishFailures = new AtomicInteger(0);
    private final AtomicInteger unPublishInvocations = new AtomicInteger(0);
    private final AtomicInteger unPublishFailures = new AtomicInteger(0);
    /**
     * @return Returns number of times published invocation
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = PUBLISH_INVOCATIONS)
    public int getPublishInvocations() {
        return publishInvocations.get();
    }
    /**
     * @param Set number of times failed publish invocation by increasing 1
     */
    public void setPublishInvocations() {
        publishInvocations.incrementAndGet();
    }
    /**
     * @return Returns number of times failed of publish invocation
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = PUBLISH_FAILURES)
    public int getPublishFailures() {
        return publishFailures.get();
    }
    /**
     * @param Set number of times failed of publish invocation by increasing 1 
     */
    public void setPublishFailures() {
        publishFailures.incrementAndGet();
    }
    /**
     * @return Returns number of times unpublish invocation
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = UNPUBLISH_INVOCATIONS)
    public int getUnPublishInvocations() {
        return unPublishInvocations.get();
    }
    /**
     * @param Set number of times failed of unpublish invocation by increasing 1
     */
    public void setUnPublishInvocations() {
        unPublishInvocations.incrementAndGet();
    }
    /**
     * @return Returns number of times failures of unpublish invocation
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = UNPUBLISH_FAILURES)
    public int getUnPublishFailures() {
        return unPublishFailures.get();
    }
    /**
     * @paramSet number of times failures of unpublish invocation by increasing 1
     */
    public void setUnPublishFailures() {
        unPublishFailures.incrementAndGet();
    }

}
