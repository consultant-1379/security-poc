/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.scriptengine.ejb.instrumentation;

import javax.enterprise.context.ApplicationScoped;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.ericsson.oss.itpf.sdk.instrument.annotation.InstrumentedBean;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Category;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.CollectionType;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Interval;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Units;
import com.ericsson.oss.itpf.sdk.instrument.annotation.MonitoredAttribute.Visibility;

/**
 * Instrumented methods that are exposed by JMX for metric measuring of method calls
 *
 * WARNING: DDP is parsing this data and Team Smart have to be notified if it changes
 */
@InstrumentedBean(description = "Script Engine Service", displayName = "script-engine")
@ApplicationScoped
public class InstrumentationBean {
    private static final MetricRegistry eServiceMetrics = new MetricRegistry();
    private static final String INSTRUMENTATION_NAME = "ScriptEngineService";
    public static final String REQUESTS_FROM_CLI = "execute";

    public Timer.Context startMethodTimer(final String methodName) {
        return getTimer(methodName).time();
    }

    /*
     * P O S T - R E Q U E S T - C A L L - M E T R I C S
     */

    /*********************************************************************************************************************************/
    @MonitoredAttribute(displayName = "number of requests from CLI", visibility = Visibility.ALL, units = Units.NONE, category = Category.PERFORMANCE, interval = Interval.FIVE_MIN, collectionType = CollectionType.TRENDSUP)
    public long getRequestsFromCLIVisits() {
        return getTimer(REQUESTS_FROM_CLI).getCount();
    }

    /*
     * P R I V A T E - M E T H O D S
     */

    private Timer getTimer(final String timerName) {
        return eServiceMetrics.timer(MetricRegistry.name(INSTRUMENTATION_NAME, timerName));
    }
}
