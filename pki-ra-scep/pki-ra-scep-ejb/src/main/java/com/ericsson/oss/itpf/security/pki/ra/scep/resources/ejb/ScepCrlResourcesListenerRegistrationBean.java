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
package com.ericsson.oss.itpf.security.pki.ra.scep.resources.ejb;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.sdk.resources.file.FileResourceEventType;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.scep.service.resource.listener.ScepCrlResourceListener;

/**
 * This class will register listeners with their resources directory path location. SCEP resource (configuration) data such as:
 * <p>
 * 1. CRLs thats are loaded in Cache when RA service started.
 * 
 * @author xchowja
 *
 */
@Startup
@Singleton
public class ScepCrlResourcesListenerRegistrationBean {

    @Inject
    private ConfigurationListener configurationListener;

    @Inject
    private Logger logger;

    private static final FileResourceEventType[] RESOURCE_EVENT_TYPES = new FileResourceEventType[] { FileResourceEventType.FILE_CREATED, FileResourceEventType.FILE_MODIFIED };

    private ScepCrlResourceListener scepCrlResourceListener = null;

    /**
     * This method is used for register the listener classes like ConfigurationListener and FileResourceListener, to notify the dynamically changed CRLs in the corresponding scepCRLPath.
     * 
     * @throws InvalidInitialConfigurationException
     *             throws whenever any initial configuration data is invalid or is not consistent
     */
    @PostConstruct
    public void registerResourceListeners() throws InvalidInitialConfigurationException {
        logger.info("registerResourceListeners method in ScepCrlResourcesListenerRegistrationBean Class");
        registerCRLResourceListener();
        logger.info("End of registerResourceListeners method in ScepCrlResourcesListenerRegistrationBean Class");
    }

    private void registerCRLResourceListener() {
        logger.info("registerCRLResourceListener method in ScepCrlResourcesListenerRegistrationBean Class");
        final String crlDirectoryPath = configurationListener.getScepCRLPath();
        if (crlDirectoryPath != null && !crlDirectoryPath.isEmpty()) {
            scepCrlResourceListener = new ScepCrlResourceListener(crlDirectoryPath, RESOURCE_EVENT_TYPES);
            if (scepCrlResourceListener != null) {
                Resources.registerListener(scepCrlResourceListener);
                logger.info("Successfully registered CRL resource listener in ScepCrlResourcesListenerRegistrationBean Class");
            }
        }
    }

    /**
     * This method is used to unregister the scepCrlResourceListener.
     * 
     */
    @PreDestroy
    public void unRegisterListeners() {
        if (scepCrlResourceListener != null) {
            Resources.unregisterListener(scepCrlResourceListener);
        }
    }
}
