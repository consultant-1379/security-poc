/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ProtectionEncodingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.UnsupportedAlgorithmException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.ExtraCertificateBuilder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.ResponseSigner;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util.SupportedAlgorithmsCacheWrapper;

/**
 * This class contains all method related to response signing. Methods:
 * <p>
 * 1. <code> public byte[] signMessage(final ResponseMessage responseMessage) throws InvalidInitialConfigurationException, IOException,
 * ProtectionEncodingException, ResponseSignerException</code>
 * <p>
 * 2. <code> public List<X509Certificate> addSignerCertandCertChainToCMPExtraCertificates() throws InvalidInitialConfigurationException. </code>
 * <p>
 * 3. <code> public String getSenderFromSignerCert() throws InvalidInitialConfigurationException</code>
 * <p>
 * 4.
 * <code> public List<X509Certificate> buildCMPExtraCertsForResponseFromManager(final ResponseMessage pKIResponseMessage) throws
 * InvalidInitialConfigurationException, CertificateException, IOException </code>
 * <p>
 *
 * @author tcsdemi
 */
public class ResponseMessageSigningHelper {

    @Inject
    InitialConfiguration configurationData;

    @Inject
    protected Logger logger;

    @Inject
    ConfigurationParamsListener configurationListener;

    @Inject
    SupportedAlgorithmsCacheWrapper supportedAlgorithmsCacheWrapper;

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
     * @param signatureAlgorithm
     *            SignatureAlgorithm is used to sign the response message.
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
    public byte[] signMessage(final String issuerName, final ResponseMessage responseMessage) throws InvalidInitialConfigurationException,
            IOException, ProtectionEncodingException, ResponseSignerException {

        final ResponseSigner messageSigner = new ResponseSigner();
        final X509Certificate signCert = configurationData.getSignerCertificate(issuerName);
        if (signCert == null) {
            logger.error("SignerCertificate is null, while forming Response Message ");
            throw new InvalidInitialConfigurationException(ErrorMessages.CERTIFICATE_IS_NULL);
        }

        final String signatureAlgorithm = signCert.getSigAlgOID();
        logger.info("Signature algorithm from signer certificate : [{}]", signatureAlgorithm);

        String sender = signCert.getSubjectDN().getName();
        final KeyPair keyPair = configurationData.getKeyPair(issuerName);
        final PrivateKey privateKey = keyPair.getPrivate();
        try {
            sender = getReverseDN(signCert.getSubjectDN().getName());
            final byte[] objID = StringUtility.toASN1ObjectIdentifier(signatureAlgorithm);

            responseMessage.setProtectionAlgorithm(objID);

        } catch (final UnsupportedAlgorithmException unsupportedAlgorithmException) {
            throw new ResponseSignerException(unsupportedAlgorithmException.getMessage(), unsupportedAlgorithmException);
        } catch (final InvalidNameException invalidNameException) {
            throw new ResponseSignerException(invalidNameException.getMessage(), invalidNameException);
        }
        return messageSigner.sign(privateKey, sender, responseMessage, signatureAlgorithm);
    }

    /**
     * This method forms a complete chain with RA certificate, RA certificate chain which will be further added directly to CMPExtraCertificates which
     * will be part of the ResponseMessage. In case of
     * IP with wait/PollResponse/KUP with wait, there are no user-certificates yet generated so for entity to verify the integrity of the message send
     * from RA, it needs RA certificates and it chain
     *
     * @param issuerName
     *            Issuer Certificate Authority name of the Node Certificate which is used as KeyStore alias name
     * @return List of extra Certificates for CMP Response
     * @throws InvalidInitialConfigurationException
     *             This exception is thrown in case signerCertificate is null.
     */
    public List<X509Certificate> addSignerCertandCertChainToCMPExtraCertificates(final String issuerName)
            throws InvalidInitialConfigurationException {

        final List<X509Certificate> cMPextraCertificates = new ArrayList<>();
        cMPextraCertificates.addAll(configurationData.getRACertificateChain(issuerName));

        return cMPextraCertificates;
    }

    /**
     * This method returns issuerName from RA certificate, this will be used while building header in the ResponseMessage. Since RA is signing the
     * responseMessage, entity will treat RA as its issuer.
     *
     * @param issuerName
     *            Issuer Certificate Authority name of the Node Certificate which is used as KeyStore alias name
     * @return sender name
     * @throws InvalidInitialConfigurationException
     *             Thrown in case signer certificate is not initilized
     */
    public String getSenderFromSignerCert(final String issuerName) throws InvalidInitialConfigurationException {
        final X509Certificate signCert = configurationData.getSignerCertificate(issuerName);
        return signCert.getSubjectDN().getName();
    }

    /**
     * This method adds RA certificate and its chain to the user certificates/chain already formed from PKI-manager. Responses sent from PKI-Manager
     * are for IP and KUP which will already have
     * userCertificates/chain.
     *
     * @param issuerName
     *            Issuer Certificate Authority name of the Node Certificate which is used as KeyStore alias name
     * @param pKIResponseMessage
     *            response Message to build CMP extra certs
     * @return chain of cmp extra certs
     * @throws CertificateException
     *             This exception is thrown in case there is an parsing exception which converting CMPCertificate into X509Certificate.
     * @throws InvalidInitialConfigurationException
     *             Thrown in case signer certificate is not initilized
     * @throws IOException
     *             is thrown when any I/O exception occurs during encoding
     */
    public List<X509Certificate> buildCMPExtraCertsForResponseFromManager(final String issuerName, final ResponseMessage pKIResponseMessage)
            throws CertificateException,
            InvalidInitialConfigurationException, IOException {
        final List<X509Certificate> raCertificateChain = new ArrayList<>();
        List<X509Certificate> extraCertsWithRAChain = null;
        raCertificateChain.addAll(addSignerCertandCertChainToCMPExtraCertificates(issuerName));
        extraCertsWithRAChain = ExtraCertificateBuilder.buildExtraCertList(raCertificateChain, pKIResponseMessage);

        final StringBuilder extraCertsDnChain = new StringBuilder();
        for (X509Certificate certificate : extraCertsWithRAChain) {
            extraCertsDnChain.append(certificate.getSubjectDN().toString());
            extraCertsDnChain.append(System.getProperty("line.separator"));
        }
        logger.debug("ExtraCerts Chain for the issuer [{}] is [{}] ", issuerName, extraCertsDnChain);
        return extraCertsWithRAChain;
    }

    private static String getReverseDN(final String dn) throws InvalidNameException {
        final LdapName ldapName = new LdapName(dn);
        final List<Rdn> rdns = ldapName.getRdns();
        final ArrayList<Rdn> rdnsList = new ArrayList<>(rdns);
        Collections.reverse(rdnsList);
        final LdapName ldapNamenew = new LdapName(rdnsList);
        return ldapNamenew.toString();

    }
}
