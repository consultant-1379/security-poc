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
package com.ericsson.oss.itpf.security.pki.manager.instrumentation.core;

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;

/**
 * Interface to provide the default methods for instrument management services
 * 
 */
public interface InstrumentationService {

    /**
     * Increases the no. of invocations by 1
     * 
     * @param metricType
     *            metric type
     * @throws IllegalArgumentException
     *             thrown when invalid action type is passed
     * @return
     */
    void setMethodInvocations(final MetricType metricType) throws IllegalArgumentException;

    /**
     * Increases the no. of failures by 1
     * 
     * @param metricType
     *            metric type * @throws IllegalArgumentException thrown when invalid action type is passed
     * @return
     */
    void setMethodFailures(final MetricType metricType) throws IllegalArgumentException;

    /**
     * Increases total execution time
     * 
     * @param metricType
     *            metric type
     * @param executionTime
     *            time taken (in milli seconds) by the current run of generate/renew/rekey
     * @throws IllegalArgumentException
     *             thrown when invalid action type is passed
     * @return
     */
    void setExecutionTimeTotalMillis(final MetricType metricType, final long executionTime) throws IllegalArgumentException;
}
