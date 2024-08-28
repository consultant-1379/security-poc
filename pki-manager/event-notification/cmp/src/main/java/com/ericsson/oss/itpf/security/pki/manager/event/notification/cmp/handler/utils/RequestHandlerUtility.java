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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils;

import java.security.cert.X509Certificate;
import java.util.Set;

import javax.inject.Inject;

import org.w3c.dom.Document;

import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.DigitalSignatureValidator;
import com.ericsson.oss.itpf.security.pki.common.util.xml.DOMUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DOMException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl.CredentialsManager;

/**
 * This class is responsible for loading and validating Request(which is of XML Format obtained from CMP).
 * 
 * @author tcsramc
 *
 */
public class RequestHandlerUtility {
    @Inject
    DigitalSignatureValidator digitalSignatureValidator;

    @Inject
    CredentialsManager credentialsManager;

    /**
     * This method is used to get the Document(XML) from the signed XML data.
     * 
     * @param xMLSignedData
     *            from which XML document needs to be generated.
     * @return document(which contains signed CMP request data).
     * @throws CredentialsManagementServiceException
     *             is thrown whenever any Error occurs in CredentialManagement.
     * @throws DigitalSignatureValidationException
     *             is thrown when digital signature validation fails.
     * @throws DOMException
     *             is thrown if any error while converting xml data(byte[]) into dom object(document).
     */
    public Document loadAndValidateRequest(final byte[] xMLSignedData) throws CredentialsManagementServiceException, DigitalSignatureValidationException, DOMException {

        final Document document = DOMUtil.getDocument(xMLSignedData);

        validateRequest(document);
        return document;

    }

    private void validateRequest(final Document document) throws CredentialsManagementServiceException, DigitalSignatureValidationException {
        final Set<X509Certificate> trustCertificates = credentialsManager.getTrustCertificateSet();
        digitalSignatureValidator.validate(document, trustCertificates);
    }

}
