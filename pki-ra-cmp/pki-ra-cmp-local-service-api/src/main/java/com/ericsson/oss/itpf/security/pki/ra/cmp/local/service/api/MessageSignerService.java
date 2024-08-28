/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ProtectionEncodingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;

/**
 * This local interface provides methods related to response signing. Methods:
 * <p>
 * 1. <code> public byte[] signMessage(final ResponseMessage responseMessage) throws InvalidInitialConfigurationException, IOException,
 * ProtectionEncodingException, ResponseSignerException</code>
 * <p>
 * 2. <code> public List<X509Certificate> addSignerCertandCertChainToCMPExtraCertificates() throws InvalidInitialConfigurationException. </code>
 * <p>
 * 3. <code> public String getSenderFromSignerCert() throws InvalidInitialConfigurationException</code>
 * <p>
 * 4. <code> public List<X509Certificate> buildCMPExtraCertsForResponseFromManager(final ResponseMessage pKIResponseMessage) throws
 * InvalidInitialConfigurationException, CertificateException, IOException </code>
 * <p>
 *
 * @author 1210241
 */
@EService
@Local
public interface MessageSignerService {

    /**
     * This method signs ResponseMessage. It gathers parameters required for signing like signerCert,keyPair,senderName and then sends responseMessage
     * for signing to ResponseSigner. It provides a
     * level of abstraction between ResponseSigner and ResponseMessages<br>
     * Note: please refer to ResponseSigner class
     *
     * @param issuerName
     *            Issuer Certificate Authority name of the Node Certificate which is used as KeyStore alias name
     * @param responseMessage
     *            response message sent to the Node
     * @return signedPollResponseMessage byte Array
     * @throws InvalidInitialConfigurationException
     *             is thrown whenever any initial configuration data is invalid or is not consistent
     * @throws IOException
     *             is thrown when any I/O exception occurs during encoding
     * @throws ProtectionEncodingException
     *             is thrown when protectionPart BER/DER encoded bytes are to be returned and there is some error while encoding the protectionPart.
     * @throws ResponseSignerException
     *             is thrown when error occurred while signing Response
     */
    public byte[] signMessage(final String issuerName, final ResponseMessage responseMessage)
            throws InvalidInitialConfigurationException, IOException, ProtectionEncodingException, ResponseSignerException;

    /**
     * This method returns issuerName from RA certificate, this will be used while building header in the ResponseMessage. Since RA is signing the
     * responseMessage, entity will treat RA as its issuer.
     *
     * @param issuerName
     *            Issuer Certificate Authority name of the Node Certificate which is used as KeyStore alias name
     * @return sender name The name of the entity from Signer certificate.
     * @throws InvalidInitialConfigurationException
     *             Thrown in case signer certificate is not initialized
     */
    public String getSenderFromSignerCert(final String issuerName) throws InvalidInitialConfigurationException;

    /**
     * This method adds RA certificate and its chain to the CMP response message created in PKI-manager. Responses sent from PKI-Manager are of Type
     * IP or KUP which will already have
     * userCertificates/chain.
     *
     * @param issuerName
     *            Issuer Certificate Authority name of the Node Certificate which is used as KeyStore alias name
     * @param pKIResponseMessage
     *            response Message to build CMP extra certs
     * @return chain of cmp extra certs
     * @throws CertificateException
     *             is thrown when any parsing exception occurs while converting CMPCertificate into X509Certificate.
     * @throws InvalidInitialConfigurationException
     *             Thrown in case signer certificate is not initialized
     * @throws IOException
     *             is thrown when any I/O exception occurs during encoding
     */
    public List<X509Certificate> buildCMPExtraCertsForResponseFromManager(final String issuerName, final ResponseMessage pKIResponseMessage)
            throws CertificateException, InvalidInitialConfigurationException, IOException;
}
