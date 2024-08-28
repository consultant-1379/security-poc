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

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.qualifier.InstrumentationQualifier;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;

/**
 * This factory is used to determine and return the instrumentation type to be returned based on the Metric Group
 * 
 */
public class InstrumentationServiceFactory {

    @Inject
    private Logger logger;

    @Inject
    @InstrumentationQualifier(MetricGroup.ENTITYMGMT)
    InstrumentationService entityManagementInstrumentationService;

    @Inject
    @InstrumentationQualifier(MetricGroup.CACERTIFICATEMGMT)
    InstrumentationService caCertificateManagementInstrumentationService;

    @Inject
    @InstrumentationQualifier(MetricGroup.ENTITYCERTIFICATEMGMT)
    InstrumentationService entityCertificateManagementInstrumentationService;

    @Inject
    @InstrumentationQualifier(MetricGroup.CRLMGMT)
    InstrumentationService crlManagementInstrumentationService;

    @Inject
    @InstrumentationQualifier(MetricGroup.REVOCATIONMGMT)
    InstrumentationService revocationManagementInstrumentationService;

    public InstrumentationService getInstrumentationService(final MetricGroup metricGroup) {
        InstrumentationService instrumentationService = null;

        switch (metricGroup) {
        case ENTITYMGMT:
            instrumentationService = entityManagementInstrumentationService;
            break;
        case CACERTIFICATEMGMT:
            instrumentationService = caCertificateManagementInstrumentationService;
            break;
        case ENTITYCERTIFICATEMGMT:
            instrumentationService = entityCertificateManagementInstrumentationService;
            break;
        case CRLMGMT:
            instrumentationService = crlManagementInstrumentationService;
            break;
        case REVOCATIONMGMT:
            instrumentationService = revocationManagementInstrumentationService;
            break;
        default:
            logger.error("Invalid metricGroup Type {}", metricGroup);
            throw new IllegalArgumentException("Invalid metricGroup Type " + metricGroup);
        }

        return instrumentationService;
    }
}