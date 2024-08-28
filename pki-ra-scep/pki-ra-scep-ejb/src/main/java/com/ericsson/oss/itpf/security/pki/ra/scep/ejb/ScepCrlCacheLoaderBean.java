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
package com.ericsson.oss.itpf.security.pki.ra.scep.ejb;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.crl.cache.util.ScepCrlCacheUtil;

/**
 * This class is a startup class which will load CRL cache through ScepCrlCacheUtil
 * 
 * @author xramdag
 *
 */
@Startup
@Singleton
public class ScepCrlCacheLoaderBean {

    @Inject
    private ScepCrlCacheUtil scepCrlCacheUtil;

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @PostConstruct
    public void load() {
        try {
            logger.info("load method in SCEPCRLCacheLoaderBean class");
            scepCrlCacheUtil.initializeCRLCache();
            logger.info("End of load method in SCEPCRLCacheLoaderBean class");
        } catch (Exception exception) {
            logger.error("Not able to initialize CRLCache for SCEP {}", exception.getMessage());
            logger.debug("Exception caught while initializing the CRL Cache for SCEP {}  ", exception);
            systemRecorder.recordError("SCEP_SERVICE_STARTUP.SERVICE_FAILED", ErrorSeverity.CRITICAL, "SCEP_SERVICE.CRL_CACHE_INITIALIZE", "SCEP_SERVICE", exception.getMessage());
        }
    }
}
