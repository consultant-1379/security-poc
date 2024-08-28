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
package com.ericsson.oss.itpf.security.pki.ra.scep.service.resource.listener;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.resources.file.FileResourceEvent;
import com.ericsson.oss.itpf.sdk.resources.file.FileResourceEventType;
import com.ericsson.oss.itpf.sdk.resources.file.listener.FileResourceListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.local.service.api.ScepCrlCacheLocalService;

/**
 * This listener will listen CRL resource directory path location. When RA service in running, if there any modification in existing CRL files or any new CRL file are added then this listener will
 * update CRL Cache for modified CRL file or new CRL file.
 * 
 * @author xchowja
 *
 */
public class ScepCrlResourceListener implements FileResourceListener {

    @Inject
    private SystemRecorder systemRecorder;

    private final String crlURI;
    private final FileResourceEventType[] crlFileEventTypes;
    private final ServiceFinderBean serviceFinder = new ServiceFinderBean();
    private final Logger logger = LoggerFactory.getLogger(ScepCrlResourceListener.class);

    public ScepCrlResourceListener(final String crlURI, final FileResourceEventType[] crlFileEventTypes) {
        this.crlURI = crlURI;
        this.crlFileEventTypes = crlFileEventTypes;
    }

    @Override
    public void onEvent(final FileResourceEvent fileResourceEvent) {
        String crlFileName = null;
        try {
            crlFileName = fileResourceEvent.getResource().getName();
            logger.info("New crl file notification received {}", crlFileName);
            logger.info("The total event types are::" + fileResourceEvent.getEventTypes());
            final ScepCrlCacheLocalService scepCrlCacheLocalService = serviceFinder.find(ScepCrlCacheLocalService.class);
            scepCrlCacheLocalService.updateCrlCache(crlFileName);

        } catch (Exception exception) {
            logger.error("Exception occurred while updating cache: {} ", exception.getCause());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PKIRASCEPService.CRLResourseListener", "Exception occurred during cache update", "PKIRASCEPService.CRLCacheUpdation",
                    ErrorSeverity.CRITICAL, "FAILURE");
        }
    }

    @Override
    public String getURI() {
        return this.crlURI;
    }

    @Override
    public FileResourceEventType[] getEventTypes() {
        return this.crlFileEventTypes;
    }
}
