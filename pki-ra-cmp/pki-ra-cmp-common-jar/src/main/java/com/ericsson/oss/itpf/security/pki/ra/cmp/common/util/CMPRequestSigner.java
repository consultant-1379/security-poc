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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.AttachedSignatureXMLBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;

/**
 * This method is used to build CMPRequest as xml and sign it to generate attached signature XML.
 *
 * @author tcsramc
 *
 */
public class CMPRequestSigner {
    @Inject
    InitialConfiguration initialConfiguration;

    /**
     * This method is used to get the signed data from the request message(which will be in XML format).
     * 
     * @param pKIRequestMessage
     *            from which XMLdata has to be formed
     * @param transactionID
     *            to identify the transaction.
     * @return signed CMP data in byte array.
     * @throws InvalidInitialConfigurationException
     *             is thrown whenever any initial configuration data is invalid or is not consistent
     * @throws DigitalSigningFailedException
     *             is thrown when failed to do digital signing for an xml
     */
    public byte[] getCMPSignedXMLData(final RequestMessage pKIRequestMessage, final String transactionID) throws InvalidInitialConfigurationException, DigitalSigningFailedException {
        final CMPRequest cmpRequest = createCMPRequest(pKIRequestMessage, transactionID);
        return signCMPRequest(cmpRequest);

    }

    /**
     * This method is used to sign the Request which is in XML format.
     *
     * @param cMPRequestToBeSigned
     *            XML data which has to be signed.
     * @return signed CMPRequest
     * @throws InvalidInitialConfigurationException
     *             is thrown whenever any initial configuration data is invalid or is not consistent
     * @throws DigitalSigningFailedException
     *             is thrown when failed to do digital signing for an xml
     */
    private byte[] signCMPRequest(final CMPRequest cMPRequestToBeSigned) throws InvalidInitialConfigurationException, DigitalSigningFailedException {

        final X509Certificate signerCertificate = initialConfiguration.getCertificateforEventSigning();
        final PrivateKey signerKey = initialConfiguration.getPrivateKeyForSigning();

        return AttachedSignatureXMLBuilder.build(signerCertificate, signerKey, cMPRequestToBeSigned);

    }

    /**
     * This method is used to return signed XML content.
     *
     * @param revocationServiceRequest
     *            XML data which has to be signed.
     * @return signedRevocationRequest
     * @throws InvalidInitialConfigurationException
     *             is thrown whenever any initial configuration data is invalid or is not consistent
     * @throws DigitalSigningFailedException
     *             is thrown when failed to do digital signing for an xml
     */
    public byte[] signRevocationRequest(final RevocationRequest revocationServiceRequest) throws InvalidInitialConfigurationException, DigitalSigningFailedException {

        final X509Certificate signerCertificate = initialConfiguration.getCertificateforEventSigning();
        final PrivateKey signerKey = initialConfiguration.getPrivateKeyForSigning();

        return AttachedSignatureXMLBuilder.build(signerCertificate, signerKey, revocationServiceRequest);

    }

    private CMPRequest createCMPRequest(final RequestMessage pKIRequestMessage, final String transactionID) {

        final CMPRequest cMPRequest = new CMPRequest();

        cMPRequest.setCmpRequest(pKIRequestMessage.toByteArray());
        cMPRequest.setTransactionId(transactionID);
        cMPRequest.setRequestType(pKIRequestMessage.getRequestType());
        cMPRequest.setSyncRequest(pKIRequestMessage.isSyncRequest());
        cMPRequest.setIssuerName(pKIRequestMessage.getIssuerName());
        return cMPRequest;
    }
}
