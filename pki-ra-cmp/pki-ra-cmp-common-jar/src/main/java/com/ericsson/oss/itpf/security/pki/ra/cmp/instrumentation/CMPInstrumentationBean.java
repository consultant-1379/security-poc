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
package com.ericsson.oss.itpf.security.pki.ra.cmp.instrumentation;

import java.util.concurrent.atomic.AtomicInteger;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.instrument.annotation.*;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Category;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.CollectionType;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Interval;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Units;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Visibility;

/**
 * <p>
 * Instrumentation bean for capturing the performance metrics of following CMP Management APIs.
 * <ul>
 * <li>CMPServiceBean.provide()</li>
 * <li>PKIConfResponseBuilder.getRequestOrResponseFromDB()</li>
 * </ul>
 * 
 * It captures the following performance metrics:
 * <ul>
 * <li>Total enrollment requests</li>
 * <li>Total enrollments succeeded</li>
 * </ul>
 * </p>
 * 
 * @author 1254288
 * 
 */
@ApplicationScoped
@InstrumentedBean(displayName = "CMP Instrumentation")
public class CMPInstrumentationBean {
    /**
     * Display names of performance metrics
     */
    private static final String ENROLLMENT_INVOCATIONS = "Number of enrollment invocations";    
    private static final String ENROLLMENT_SUCCESS = "Number of succeeded enrollments";
      

    /**
     * Variable declarations that capture performance metrics
     */
    private final AtomicInteger enrollmentInvocations = new AtomicInteger(0);
    private final AtomicInteger enrollmentSuccess = new AtomicInteger(0);
    
    
    /**
     * Returns no. of times enrollment was invoked
     * 
     * @return the count
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = ENROLLMENT_INVOCATIONS)
    public int getEnrollmentInvocations() {
        return enrollmentInvocations.get();
    }

    /**
     * Increases the no. of invocations on enrollment by 1
     * 
     */
    public void setEnrollmentInvocations() {
        enrollmentInvocations.incrementAndGet();
    }   

    /**
     * Returns no. of times enrollment has succeeded
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = ENROLLMENT_SUCCESS)
    public int getEnrollmentSuccess() {
        return enrollmentSuccess.get();
    }

    /**
     * Increases the no. of success on enrollment by 1
     * 
     */
    public void setEnrollmentSuccess() {
        enrollmentSuccess.incrementAndGet();
    }    

}
