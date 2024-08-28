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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationResponse;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.AttachedSignatureXMLBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.MarshalException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl.CredentialsManager;

/**
 * This class is used to build Signed CMP Response.
 * 
 * @author tcsramc
 *
 */
public class SignedResponseBuilder {

    @Inject
    CredentialsManager credentialsManager;

    /**
     * This method is used to digitally sign the CMPResponse Message.
     * 
     * @param cMPResponse
     *            Contains the data that holds the response message
     * @return signed response message
     * @throws DigitalSigningFailedException
     *             is thrown if XML signing fails
     * @throws CredentialsManagementServiceException
     *             is thrown if any internal service error occurs in credential Management.
     * @throws MarshalException
     *             is thrown if any error occurs while marshaling the data into document(signed XML).
     */
    public byte[] buildSignedCMPResponse(final CMPResponse cMPResponse) throws DigitalSigningFailedException, CredentialsManagementServiceException, MarshalException {

        final X509Certificate certificate = credentialsManager.getSignerCertificate();
        final PrivateKey signerKey = credentialsManager.getSignerPrivateKey();

        final byte[] signedCMPResponse = AttachedSignatureXMLBuilder.build(certificate, signerKey, cMPResponse);

        return signedCMPResponse;

    }

    /**
     * This method is used to digitally sign the RevocationResponse Message.
     * 
     * @param revocationResponse
     *            Contains the data that holds the response message
     * @return signed response message
     * @throws DigitalSigningFailedException
     *             is thrown if XML signing fails.
     * @throws CredentialsManagementServiceException
     *             is thrown if any internal service error occurs in credential Management.
     * @throws MarshalException
     *             is thrown if any error occurs while marshaling the data into document(signed XML).
     */
    public byte[] buildSignedRevocationResponse(final RevocationResponse revocationResponse) throws DigitalSigningFailedException, CredentialsManagementServiceException, MarshalException {

        final X509Certificate certificate = credentialsManager.getSignerCertificate();
        final PrivateKey signerKey = credentialsManager.getSignerPrivateKey();

        final byte[] signedRevocationResponse = AttachedSignatureXMLBuilder.build(certificate, signerKey, revocationResponse);

        return signedRevocationResponse;

    }

}
