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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.util;

import java.security.cert.X509Certificate;
import java.util.Set;

import javax.inject.Inject;

import org.w3c.dom.Document;

import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.DigitalSignatureValidator;
import com.ericsson.oss.itpf.security.pki.common.util.xml.DOMUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DOMException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;

/**
 * This class is used to get XML document from the CMPResponse.
 * 
 * @author tcsramc
 *
 */
public class PKIManagerResponseProcessor {

    @Inject
    InitialConfiguration initialConfiguration;

    @Inject
    DigitalSignatureValidator digitalSignatureValidator;

    /**
     * This method will get the XML Response data and then validate the signature on the received XML.
     * 
     * @param signedXMLData
     *            from which document has to be extracted.
     * @return XML document.
     * @throws InvalidInitialConfigurationException
     *             is thrown whenever any initial configuration data is invalid or is not consistent
     * @throws DigitalSignatureValidationException
     *             is thrown if digitalsignature validation fails.
     * @throws DOMException
     *             is thrown when failed to build or parse a Document object.
     */
    public Document loadAndValidateResponse(final byte[] signedXMLData) throws InvalidInitialConfigurationException, DigitalSignatureValidationException, DOMException {
        final Document document = DOMUtil.getDocument(signedXMLData);
        validateResponse(document);
        return document;
    }

    private void validateResponse(final Document document) throws InvalidInitialConfigurationException, DigitalSignatureValidationException {
        final Set<X509Certificate> trustCertificates = initialConfiguration.getCaCertificateSet();
        digitalSignatureValidator.validate(document, trustCertificates);
    }

}
