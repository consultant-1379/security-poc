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
package com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.service;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.InstrumentationService;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.metrics.EndEntityCertificateManagementInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.core.qualifier.InstrumentationQualifier;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;

/**
 * Instrumentation Service Implementation class for EntityCertificationManagement
 * 
 */
@InstrumentationQualifier(MetricGroup.ENTITYCERTIFICATEMGMT)
public class EntityCertificateManagementInstrumentationService implements InstrumentationService {

    @Inject
    private Logger logger;
    
    @Inject
    EndEntityCertificateManagementInstrumentationBean entityCertificateManagementInstrumentationBean;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.ejb.instrumentation.service .PkiManagerInstrumentationService #setMethodInvocations(com.ericsson.oss.itpf
     * .security.pki.manager.ejb.instrumentation.annotation.MetricType)
     */
    @Override
    public void setMethodInvocations(final MetricType metricType) throws IllegalArgumentException {
        switch (metricType) {
        case GENERATE:
            entityCertificateManagementInstrumentationBean.setGenerateMethodInvocations();
            break;
        case RENEW:
            entityCertificateManagementInstrumentationBean.setRenewMethodInvocations();
            break;
        case REKEY:
            entityCertificateManagementInstrumentationBean.setRekeyMethodInvocations();
            break;
        default:
            logger.error("Invalid MetricType found {}", metricType);
            throw new IllegalArgumentException("Invalid MetricType found "+ metricType);
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.ejb.instrumentation.service .PkiManagerInstrumentationService #setMethodFailures(com.ericsson.oss.itpf.
     * security.pki.manager.ejb.instrumentation.annotation.MetricType)
     */
    @Override
    public void setMethodFailures(final MetricType metricType) throws IllegalArgumentException {
        switch (metricType) {
        case GENERATE:
            entityCertificateManagementInstrumentationBean.setGenerateMethodFailures();
            break;
        case RENEW:
            entityCertificateManagementInstrumentationBean.setRenewMethodFailures();
            break;
        case REKEY:
            entityCertificateManagementInstrumentationBean.setRekeyMethodFailures();
            break;
        default:
            logger.error("Invalid MetricType found {}", metricType);
            throw new IllegalArgumentException("Invalid MetricType found "+ metricType);
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.ejb.instrumentation.service .PkiManagerInstrumentationService #setExecutionTimeTotalMillis(com.ericsson
     * .oss.itpf.security.pki.manager.ejb.instrumentation.annotation.MetricType)
     */
    @Override
    public void setExecutionTimeTotalMillis(final MetricType metricType, final long executionTime) throws IllegalArgumentException {
        switch (metricType) {
        case GENERATE:
            entityCertificateManagementInstrumentationBean.setGenerateExecutionTimeTotalMillis(executionTime);
            break;
        case RENEW:
            entityCertificateManagementInstrumentationBean.setRenewExecutionTimeTotalMillis(executionTime);
            break;
        case REKEY:
            entityCertificateManagementInstrumentationBean.setRekeyExecutionTimeTotalMillis(executionTime);
            break;
        default:
            logger.error("Invalid MetricType found {}", metricType);
            throw new IllegalArgumentException("Invalid MetricType found "+ metricType);
        }
    }

}
