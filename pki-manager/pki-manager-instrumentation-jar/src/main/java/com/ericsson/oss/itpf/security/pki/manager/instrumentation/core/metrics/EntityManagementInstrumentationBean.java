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
 * Instrumentation bean for capturing the performance metrics of following Entity Management APIs.
 * <ul>
 * <li>createEntity()</li>
 * <li>createEntityAndGetEnrollmentInfo</li>
 * <li>getEntity()</li>
 * <li>updateEntity()</li>
 * <li>updateEntityAndGetEnrollmentInfo</li>
 * <li>deleteEntity</li>
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
 * @author tcspred
 * 
 */
@ApplicationScoped
@InstrumentedBean(displayName = "Entity Management Daily Totals")
public class EntityManagementInstrumentationBean {

    /**
     * Display names of performance metrics
     */
    public static final String DESC_CREATE_INVOCATIONS = "Number of invocations on create method.";
    public static final String DESC_CREATE_FAILURES = "Number of times create method failed.";
    public static final String DESC_CREATE_EXEC_TIME_TOTAL = "Total execution time of create method (ms).";

    public static final String DESC_UPDATE_INVOCATIONS = "Number of invocations on update method.";
    public static final String DESC_UPDATE_FAILURES = "Number of times update method failed.";
    public static final String DESC_UPDATE_EXEC_TIME_TOTAL = "Total execution time of update method (ms).";

    public static final String DESC_DELETE_INVOCATIONS = "Number of invocations on delete method.";
    public static final String DESC_DELETE_FAILURES = "Number of times delete method failed.";
    public static final String DESC_DELETE_EXEC_TIME_TOTAL = "Total execution time of delete method (ms).";

    public static final String DESC_READ_INVOCATIONS = "Number of invocations on read method.";
    public static final String DESC_READ_FAILURES = "Number of times read method failed.";
    public static final String DESC_READ_EXEC_TIME_TOTAL = "Total execution time of read method (ms).";

    /**
     * Variable declarations that capture performance metrics
     */
    private final AtomicInteger createMethodInvocations = new AtomicInteger(0);
    private final AtomicInteger createMethodFailures = new AtomicInteger(0);
    private final AtomicLong createExecutionTimeTotalMillis = new AtomicLong(0);

    private final AtomicInteger updateMethodInvocations = new AtomicInteger(0);
    private final AtomicInteger updateMethodFailures = new AtomicInteger(0);
    private final AtomicLong updateExecutionTimeTotalMillis = new AtomicLong(0);

    private final AtomicInteger deleteMethodInvocations = new AtomicInteger(0);
    private final AtomicInteger deleteMethodFailures = new AtomicInteger(0);
    private final AtomicLong deleteExecutionTimeTotalMillis = new AtomicLong(0);

    private final AtomicInteger readMethodInvocations = new AtomicInteger(0);
    private final AtomicInteger readMethodFailures = new AtomicInteger(0);
    private final AtomicLong readExecutionTimeTotalMillis = new AtomicLong(0);

    /**
     * Returns no. of times create method was invoked
     * 
     * @return the count
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_CREATE_INVOCATIONS)
    public int getCreateMethodInvocations() {
        return createMethodInvocations.get();
    }

    /**
     * Increases the no. of invocations on create method by 1
     * 
     */
    public void setCreateMethodInvocations() {
        createMethodInvocations.incrementAndGet();
    }

    /**
     * Returns no. of times update method was invoked
     * 
     * @return the count
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_UPDATE_INVOCATIONS)
    public int getUpdateMethodInvocations() {
        return updateMethodInvocations.get();
    }

    /**
     * Increases the no. of invocations on update method by 1
     * 
     */
    public void setUpdateMethodInvocations() {
        updateMethodInvocations.incrementAndGet();
    }

    /**
     * Returns no. of times delete method was invoked
     * 
     * @return the count
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_DELETE_INVOCATIONS)
    public int getDeleteMethodInvocations() {
        return deleteMethodInvocations.get();
    }

    /**
     * Increases the no. of invocations on delete method by 1
     * 
     */
    public void setDeleteMethodInvocations() {
        deleteMethodInvocations.incrementAndGet();
    }

    /**
     * Returns no. of times retrieve method was invoked
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_READ_INVOCATIONS)
    public int getReadMethodInvocations() {
        return readMethodInvocations.get();
    }

    /**
     * Increases the no. of invocations on retrieve method by 1
     * 
     */
    public void setReadMethodInvocations() {
        readMethodInvocations.incrementAndGet();
    }

    /**
     * Returns no. of times create method has failed
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_CREATE_FAILURES)
    public int getCreateMethodFailures() {
        return createMethodFailures.get();
    }

    /**
     * Increases the no. of failures of create method by 1
     * 
     */
    public void setCreateMethodFailures() {
        createMethodFailures.incrementAndGet();
    }

    /**
     * Returns no. of times update method has failed
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_UPDATE_FAILURES)
    public int getUpdateMethodFailures() {
        return updateMethodFailures.get();
    }

    /**
     * Increases the no. of failures of update method by 1
     * 
     */
    public void setUpdateMethodFailures() {
        updateMethodFailures.incrementAndGet();
    }

    /**
     * Returns no. of times delete method has failed
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_DELETE_FAILURES)
    public int getDeleteMethodFailures() {
        return deleteMethodFailures.get();
    }

    /**
     * Increases the no. of failures of delete method by 1
     * 
     */
    public void setDeleteMethodFailures() {
        deleteMethodFailures.incrementAndGet();
    }

    /**
     * Returns no. of times retrieve method has failed
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.NONE, visibility = Visibility.INTERNAL, displayName = DESC_READ_FAILURES)
    public int getReadMethodFailures() {
        return readMethodFailures.get();
    }

    /**
     * Increases the no. of failures of retrieve method by 1
     * 
     */
    public void setReadMethodFailures() {
        readMethodFailures.incrementAndGet();
    }

    /**
     * Returns the total execution time of create method in milli seconds
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.MILLISECONDS, visibility = Visibility.INTERNAL, displayName = DESC_CREATE_EXEC_TIME_TOTAL)
    public long getCreateExecutionTimeTotalMillis() {
        return createExecutionTimeTotalMillis.get();
    }

    /**
     * Increases total execution time of create method by the value given in execution time
     * 
     * @param executionTime
     *            time taken(in milli seconds) by the current run of create method
     */
    public void setCreateExecutionTimeTotalMillis(final long executionTime) {
        createExecutionTimeTotalMillis.addAndGet(executionTime);
    }

    /**
     * Returns the total execution time of update method in milli seconds
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.MILLISECONDS, visibility = Visibility.INTERNAL, displayName = DESC_UPDATE_EXEC_TIME_TOTAL)
    public long getUpdateExecutionTimeTotalMillis() {
        return updateExecutionTimeTotalMillis.get();
    }

    /**
     * Increases total execution time of update method by the value given in execution time
     * 
     * @param executionTime
     *            time taken(in milli seconds) by the current run of update method
     */
    public void setUpdateExecutionTimeTotalMillis(final long executionTime) {
        updateExecutionTimeTotalMillis.addAndGet(executionTime);
    }

    /**
     * Returns the total execution time of delete method in milli seconds
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.MILLISECONDS, visibility = Visibility.INTERNAL, displayName = DESC_DELETE_EXEC_TIME_TOTAL)
    public long getDeleteExecutionTimeTotalMillis() {
        return deleteExecutionTimeTotalMillis.get();
    }

    /**
     * Increases total execution time of delete method by the value given in execution time
     * 
     * @param executionTime
     *            time taken(in milli seconds) by the current run of delete method
     */
    public void setDeleteExecutionTimeTotalMillis(final long executionTime) {
        deleteExecutionTimeTotalMillis.addAndGet(executionTime);
    }

    /**
     * Returns the total execution time of retrieve method in milli seconds
     * 
     * @return
     */
    @MonitoredAttribute(category = Category.PERFORMANCE, collectionType = CollectionType.TRENDSUP, interval = Interval.FIVE_MIN, units = Units.MILLISECONDS, visibility = Visibility.INTERNAL, displayName = DESC_READ_EXEC_TIME_TOTAL)
    public long getReadExecutionTimeTotalMillis() {
        return readExecutionTimeTotalMillis.get();
    }

    /**
     * Increases total execution time of retrieve method by the value given in execution time
     * 
     * @param executionTime
     *            time taken(in milli seconds) by the current run of retrieve method
     */
    public void setReadExecutionTimeTotalMillis(final long executionTime) {
        readExecutionTimeTotalMillis.addAndGet(executionTime);
    }
}
