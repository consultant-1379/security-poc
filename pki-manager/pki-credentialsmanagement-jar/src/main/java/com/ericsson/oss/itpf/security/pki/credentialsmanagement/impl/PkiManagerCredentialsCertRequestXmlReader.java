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
package com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl;

import java.io.File;
import java.net.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.constants.Constants;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.xml.model.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;

/**
 * This class is used to parse the given XML file and load into a Java object ApplicationsType which is to be used to generate pki-manager credentials.
 * 
 * @author tcsnapa
 *
 */
public class PkiManagerCredentialsCertRequestXmlReader {

    @Inject
    Logger logger;

    private CertificateType certificateType = null;

    /**
     * This method will load the given XML file into a Java object ApplicationsType using JaxbUtil.
     * 
     * @throws CredentialsManagementServiceException
     *             is thrown when error occurs while loading XML file into Java object.
     */
    public void loadDataFromXML() throws CredentialsManagementServiceException {
        ApplicationsType applicationsType;
        final String xmlFilePath = Constants.PKI_CREDENTIALS_REQUEST_XML_FILE_PATH;
        final File file = new File(xmlFilePath);
        if (file.exists()) {
            try {
                final URL url = getClass().getResource(Constants.PKI_CREDENTIALS_REQUEST_XSD_FILE_PATH).toURI().toURL();
                applicationsType = JaxbUtil.getObject(file, ApplicationsType.class, url);
                certificateType = applicationsType.getApplication().get(0).getCertificates().getCertificate().get(0);
            } catch (final MalformedURLException | URISyntaxException e) {
                logger.error(ErrorMessages.FAILED_TO_CONSTRUCT_URL, e.getMessage());
                throw new CredentialsManagementServiceException(ErrorMessages.FAILED_TO_CONSTRUCT_URL + e.getMessage(), e);
            } catch (final CommonRuntimeException e) {
                logger.error(ErrorMessages.INVALID_XML_PKI_CREDM_CERT_REQUEST, e.getMessage());
                throw new CredentialsManagementServiceException(ErrorMessages.INVALID_XML_PKI_CREDM_CERT_REQUEST + e.getMessage(), e);
            }
        } else {
            logger.error("{} at the given path {} ", ErrorMessages.PKI_CREDM_CERT_REQUEST_XML_FILE_NOT_FOUND, xmlFilePath);
            throw new CredentialsManagementServiceException(ErrorMessages.PKI_CREDM_CERT_REQUEST_XML_FILE_NOT_FOUND + " at the given path " + xmlFilePath);
        }
    }

    public SubjectType getSubjectType() {
        return certificateType.getTbsCertificate().getSubject();
    }

    public KeyPairType getKeyPairType() {
        return certificateType.getKeyPair();
    }

    public StoreType getStore(final KeyStoreType keyStoreType) throws CredentialsManagementServiceException {
        switch (keyStoreType) {
        case PKCS12:
            return certificateType.getKeyStore().get(0).getPkcs12KeyStore();
        case JKS:
            return certificateType.getTrustStore().get(0).getJksTrustStore();
        default:
            throw new CredentialsManagementServiceException(ErrorMessages.KEYSTORE_TYPE_IS_NOT_VALID);
        }
    }

    public String getEndEntityProfileName() {
        return certificateType.getEndEntityProfileName();
    }

    public String getOverlapPeriod() {
        return certificateType.getOverlapPeriod();
    }
}
