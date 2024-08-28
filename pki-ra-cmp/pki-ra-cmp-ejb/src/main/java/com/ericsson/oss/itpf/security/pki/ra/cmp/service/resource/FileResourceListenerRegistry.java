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

package com.ericsson.oss.itpf.security.pki.ra.cmp.service.resource;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.sdk.resources.file.FileResourceEventType;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.service.resource.listener.*;

/**
 * This class will register listeners with their resources directory path location. CMP resource (configuration) data such as:
 * <p>
 * 1. VendorCertificates which are External trusts, are required in verifying Digital Signature of the RequestMessage, in case integrity of request message to be verified is through VendorCredentials
 * i.e for InitializationRequest
 * <p>
 * 2. CACertificates which are Internal trusts, are required in verifying Digital Signature of KeyUpdateRequest
 * <p>
 * 3. CRLs thats are loaded in Cache when RA service started.
 *
 * @author tcsmanp
 */
@Startup
@Singleton
public class FileResourceListenerRegistry {

    @Inject
    private ConfigurationParamsListener configurationListener;

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    private VendorCertificatesResourceListener vendorCertificatesResourceListener = null;

    private CaCertificatesResourceListener caCertificatesResourceListener = null;

    private CrlResourceListener crlResourceListener = null;

    private static final FileResourceEventType[] RESOURCE_EVENT_TYPES = new FileResourceEventType[] { FileResourceEventType.FILE_CREATED, FileResourceEventType.FILE_MODIFIED };

    /**
     * This method will register listeners for VendorCertificates, CACertificates and CRLs with their resources directory path location.
     */
    @PostConstruct
    public void registerResourceListeners() {
        logger.info("registerResourceListeners method in TrustResourcesListenerBean");
        try {
            registerVendorCertificatesResourceListener();
            registerCaCertificatesResourceListener();
            registerCrlResourceListener();
        } catch (final Exception exception) {
            logger.error(ErrorMessages.FAILED_TO_REGISTER_RESOURCES_LISTENERS, exception.getMessage());
            logger.debug("Not able to register resources listeners. New/updated Certficates and CRLs will not be available in CMP ", exception);
            systemRecorder.recordError("CMP_SERVICE_STARTUP.REGISTER_RESOURCES_LISTENER_FAILED", ErrorSeverity.CRITICAL,
                    "CMP_SERVICE.REGISTER_RESOURCE_LISTENERS", "CMP_SERVICE",
                    ErrorMessages.FAILED_TO_REGISTER_RESOURCES_LISTENERS);
        }
        logger.info("Successfully registered resources listeners with listen directory path location for internal/external trusts and CRL");
    }

    private void registerVendorCertificatesResourceListener() throws IllegalArgumentException, IllegalStateException {
        final String listenDirectoryPath = getListenDirectoryPath(configurationListener.getVendorCertPath());
        if (listenDirectoryPath != null && !listenDirectoryPath.isEmpty()) {
            vendorCertificatesResourceListener = new VendorCertificatesResourceListener(listenDirectoryPath, RESOURCE_EVENT_TYPES);
            Resources.registerListener(vendorCertificatesResourceListener);
            logger.info("Successfully registered Vendor Certificates resource listener");
        }
    }

    private void registerCaCertificatesResourceListener() throws IllegalArgumentException, IllegalStateException {
        final String listenDirectoryPath = getListenDirectoryPath(configurationListener.getCACertPath());

        if (listenDirectoryPath != null && !listenDirectoryPath.isEmpty()) {
            caCertificatesResourceListener = new CaCertificatesResourceListener(listenDirectoryPath, RESOURCE_EVENT_TYPES);
            Resources.registerListener(caCertificatesResourceListener);
            logger.info("Successfully registered CA Certificates resource listener");
        }
    }

    private void registerCrlResourceListener() throws IllegalArgumentException, IllegalStateException {
        final String crlDirectoryPath = configurationListener.getCRLPath();

        if (crlDirectoryPath != null && !crlDirectoryPath.isEmpty()) {
            crlResourceListener = new CrlResourceListener(crlDirectoryPath, RESOURCE_EVENT_TYPES);
            Resources.registerListener(crlResourceListener);
            logger.info("Successfully registered CRL resource listener");
        }
    }

    @PreDestroy
    private void unRegisterListeners() {
        try {
            if (vendorCertificatesResourceListener != null) {
                Resources.unregisterListener(vendorCertificatesResourceListener);
            }

            if (caCertificatesResourceListener != null) {
                Resources.unregisterListener(caCertificatesResourceListener);
            }

            if (crlResourceListener != null) {
                Resources.unregisterListener(crlResourceListener);
            }
        } catch (final IllegalArgumentException illegalArgumentException) {
            logger.error(ErrorMessages.FAILED_TO_UNREGISTER_RESOURCES_LISTENERS, illegalArgumentException.getMessage());
            logger.debug("Not able to unregister resources listeners with listen directory path location for internal/external trusts and CRL ",
                    illegalArgumentException);
        } catch (final IllegalStateException illegalStateException) {
            logger.error(ErrorMessages.FAILED_TO_UNREGISTER_RESOURCES_LISTENERS, illegalStateException.getMessage());
            logger.debug("Not able to unregister resources listeners with listen directory path location for internal/external trusts and CRL ",
                    illegalStateException);
        }
    }

    private String getListenDirectoryPath(final String certificatesPath) {
        final StringBuilder listenDirectoryPath = new StringBuilder();
        final String lsPath = listenDirectoryPath.toString();
        if (certificatesPath != null && !certificatesPath.isEmpty()) {
            final String[] certificatesPathSplit = certificatesPath.split("/");
            for (int i = 0; i < certificatesPathSplit.length - 1; i++) {
                listenDirectoryPath.append(certificatesPathSplit[i]).append("/");
            }
        }
        logger.info("Listen resource directory path {}" , lsPath);
        return listenDirectoryPath.toString().trim();
    }
}
