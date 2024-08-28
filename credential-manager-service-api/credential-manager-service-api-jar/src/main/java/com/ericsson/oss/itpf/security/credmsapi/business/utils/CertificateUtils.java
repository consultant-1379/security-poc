/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmsapi.CredMServiceWrapper;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.business.CredentialReaderFactory;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;

public class CertificateUtils {

    private static final Logger LOG = LogManager.getLogger(CertificateUtils.class);

    public static PKCS10CertificationRequest generatePKCS10Request(final String signatureAlgorithm, final X500Name x500Name, final KeyPair keyPair, final Attribute[] attributes)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

        final JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(x500Name, keyPair.getPublic());

        if (attributes != null) {
            for (final Attribute attribute : attributes) {
                csrBuilder.addAttribute(attribute.getAttrType(), attribute.getAttributeValues());
            }
        }

        final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);

        PKCS10CertificationRequest csr = null;
        try {
            final ContentSigner signer = signerBuilder.build(keyPair.getPrivate());
            csr = csrBuilder.build(signer);
        } catch (final OperatorCreationException e) {
            LOG.error(ErrorMsg.API_ERROR_BUSINESS_UTILS_CREATE_CSR);
        }

        return csr;

    }

    public static PKCS10CertificationRequest generatePKCS10Request(final String signatureAlgorithm, final CredentialManagerEntity entity, final KeyPair keyPair, final Attribute[] attributes)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

        // X509Name name = new
        // X509Name(entity.getSubject().retrieveSubjectDN());
        final X500Name name = new X500Name(entity.getSubject().retrieveSubjectDN());

        // qdavges
        return generatePKCS10Request(signatureAlgorithm, name, keyPair, attributes);

    }

    /*
     * Retrieve certificatedIdentifier from input KeyStore: if KeyStore is empty or certificate cannot be found it returns null
     */
    public static CredentialManagerCertificateIdentifier retrieveCertificateId(final KeystoreInfo keyStoreCert) {

        String storeFilePath = null;

        /**
         * Validate settings into keyStoreCert
         */
        if (keyStoreCert.getCertificateLocation() != null && !keyStoreCert.getCertificateLocation().isEmpty()) {
            storeFilePath = keyStoreCert.getCertificateLocation();
        } else if (keyStoreCert.getKeyAndCertLocation() != null && !keyStoreCert.getKeyAndCertLocation().isEmpty()) {
            storeFilePath = keyStoreCert.getKeyAndCertLocation();
        } else {
            LOG.warn("Retrieving certificate Id: keyStore location not existing.");
            return null;
        }

        LOG.info("Retrieving certificate Id: " + storeFilePath);

        /**
         * check if the keystore exists
         */
        final File storeFile = new File(storeFilePath);
        if (!storeFile.exists()) {
            LOG.warn("Retrieving certificate Id: keystore file doesn't exist in " + storeFilePath);
            return null;
        }

        /**
         * Read certificate from Storage
         */
        Certificate certificate = null;

        final CredentialReaderFactory crf = new CredentialReaderFactory();
        try {
            final CredentialReader credRKS = crf.getCredentialreaderInstance(StorageFormatUtils.getCertFormatString(keyStoreCert.getCertFormat()), storeFilePath, keyStoreCert.getKeyStorePwd());

            certificate = credRKS.getCertificate(keyStoreCert.getAlias());

            if (certificate == null) {
                LOG.warn("Retrieving certificate Id: CERTIFICATE IS NULL " + storeFilePath);
                return null; // certificate not found
            }

        } catch (final StorageException e) {

            LOG.warn(ErrorMsg.API_ERROR_BUSINESS_GET_CERTKS, keyStoreCert.getAlias());
            return null; // invalid certificate format 
        }

        /**
         * Certificate format conversion to X509
         */
        X509Certificate x509Certificate = null;
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            final InputStream inputStream = new ByteArrayInputStream(certificate.getEncoded());
            x509Certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (final CertificateException e) {
            LOG.error(ErrorMsg.API_ERROR_BUSINESS_CREATE_CERTSTREAM, keyStoreCert.getAlias());
            return null;
        }

        final CredentialManagerCertificateIdentifier certId = new CredentialManagerCertificateIdentifier(x509Certificate.getSubjectX500Principal(), x509Certificate.getIssuerX500Principal(),
                x509Certificate.getSerialNumber());

        return certId;
    } // end of retrieveCertificateId

    /**
     * buildIdentifier
     * 
     * @param certificate
     * @return
     */
    public static CredentialManagerCertificateIdentifier buildIdentifier(final X509Certificate certificate) {
        if (certificate != null) {
            return new CredentialManagerCertificateIdentifier(certificate.getSubjectX500Principal(), certificate.getIssuerX500Principal(), certificate.getSerialNumber());
        }
        return null;
    }

    /**
     * buildIdentifierFromStrings
     * 
     * @param issuerDN
     *            : string representation of an X.500 distinguished name for issuer
     * @param subjectDN
     *            : string representation of an X.500 distinguished name for subject
     * @param certificateSN
     *            : certificate serial number in string format
     * 
     * @return CredentialManagerCertificateIdentifier
     */
    public static CredentialManagerCertificateIdentifier buildIdentifierFromStrings(final String issuerDN, final String subjectDN, final String certificateSN) {

        if (issuerDN == null || issuerDN.isEmpty()) {
            return null;
        }

        if (subjectDN == null || subjectDN.isEmpty()) {
            return null;
        }

        if (certificateSN == null || certificateSN.isEmpty()) {
            return null;
        }

        X500Principal x500Issuer;
        X500Principal x500Subject;
        BigInteger serialNumber;

        try {
            x500Issuer = new X500Principal(issuerDN);
            x500Subject = new X500Principal(subjectDN);
            serialNumber = new BigInteger(certificateSN);
        } catch (NullPointerException | IllegalArgumentException e) {
            return null;
        }

        CredentialManagerCertificateIdentifier certificateIdentifier = new CredentialManagerCertificateIdentifier(x500Subject, x500Issuer, serialNumber);

        return certificateIdentifier;
    }

    /**
     * checkDateValidity
     * 
     * performs a checkValidity on the certificate but using a date shifter PRE_EXPIRED_SCREW days in the future, and logs N kind (warnTimers list) of warnings X days before expiration
     * 
     * @param certificate
     * @param firstDayRun
     * @param warnTimers
     * @param entityName
     * @throws CertificateExpiredException
     * @throws CertificateNotYetValidException
     */
    public static void checkDateValidity(final X509Certificate certificate, final boolean firstDayRun, final List<String> warnTimers, final String entityName, final int timer,
            final CredMServiceWrapper serviceWrapp) throws CertificateExpiredException, CertificateNotYetValidException {

        final Calendar c = Calendar.getInstance();
        final Date currentTime = new Date();

        c.setTime(currentTime); //sets current time

        c.add(Calendar.DATE, timer);
        certificate.checkValidity(c.getTime()); //if expired or almost an exception is thrown and returns

        /**
         * Warnings Management
         **/
        //obtains the certificate expiration date in Date format and the currentTime in Calendar format
        final Date certExpDate = certificate.getNotAfter();
        final Calendar currentDate = Calendar.getInstance();
        currentDate.setTime(currentTime);
        //reverts the expiration date 'entryTime' days before, then check that currentTime is the exact same day,
        //ignoring hour and below (minutes etc.)
        for (String entryTime : warnTimers) {
            c.setTime(certExpDate);
            c.add(Calendar.DATE, -Integer.parseInt(entryTime));

            if (firstDayRun && currentDate.get(Calendar.DAY_OF_YEAR) == c.get(Calendar.DAY_OF_YEAR) && currentDate.get(Calendar.YEAR) == c.get(Calendar.YEAR)) {
                LOG.warn("Attention, certificate for " + entityName + " is going to expire in " + entryTime + " days!");
                serviceWrapp.printErrorOnSystemRecorder("Certificate is going to expire in " + entryTime + " days", ErrorSeverity.WARNING, "Credential Manager CLI", entityName, null);
                return;
            }
        }
    }

    /**
     * buildDNfromOids: builds an LdapName fixing the one read from certificate owner field
     * 
     * @param nameDN
     */
    public static LdapName buildDNfromOids(final String nameDN) {

        final Map<String, String> dnOidMap = new HashMap<String, String>();
        dnOidMap.put("2.5.4.4", "SURNAME"); // OID for SURNAME
        dnOidMap.put("2.5.4.12", "T"); // OID for TITLE
        dnOidMap.put("2.5.4.5", "SN"); // OID for SerialNUMBER
        dnOidMap.put("2.5.4.42", "GIVENNAME"); // OID for GIVENNAME
        dnOidMap.put("2.5.4.46", "DN"); // OID for DNQUALIFIER

        final X500Principal dn = new X500Principal(nameDN);
        final String certIssuerStr = dn.getName(X500Principal.RFC2253, dnOidMap);
        LdapName ldap = null;
        try {
            ldap = new LdapName(certIssuerStr);
        } catch (InvalidNameException e) {
            //do nothing and return null
        }
        return ldap;
    }

}
