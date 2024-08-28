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
package com.ericsson.oss.itpf.security.pki.common.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.*;
import java.util.*;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.keystore.constants.KeyStoreErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateConversionException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateUtilityException;

/**
 * This class contains common utility methods for Certificate related operations like Certificate conversion from byte array to X509Certificate.
 * 
 * @author xjagcho
 * 
 **/
public final class CertificateUtility {

    private CertificateUtility() {

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateUtility.class);

    /**
     * This method is used to get the x509 certificate from the given Byte Array.
     * 
     * @param certificate
     *            data as in byte[].
     * 
     * @return X509Certificate is the generated certificate from the byte array.
     * 
     * @throws CertificateConversionException
     *             is thrown if it is invalid certificate content in the provided byte array or if the stream is not closed properly.
     * 
     */
    public static X509Certificate getCertificateFromByteArray(final byte[] certificate) throws CertificateConversionException {
        LOGGER.info("Start of getCertificateFromByteArray method in CertificateUtility class ");
        CertificateFactory certificateFactory = null;
        X509Certificate x509Certificate = null;
        ByteArrayInputStream certificatebytearray = new ByteArrayInputStream(certificate);
        try {
            certificateFactory = CertificateFactory.getInstance(Constants.X509);
            certificatebytearray = new ByteArrayInputStream(certificate);
            x509Certificate = (X509Certificate) certificateFactory.generateCertificate(certificatebytearray);
        } catch (final CertificateException certificateException) {
            LOGGER.error("Caught exception while preparing X509Certificate using certificate byte[]");
            throw new CertificateConversionException(KeyStoreErrorMessages.CERTIFICATE_CONVERSION_FAILED, certificateException);

        } finally {
            closeInputStream(certificatebytearray);
        }
        LOGGER.info("End of getCertificateFromByteArray method in CertificateUtility class ");
        return x509Certificate;

    }

    /**
     * @param certificatebytearray
     */
    private static void closeInputStream(final ByteArrayInputStream certificatebytearray) throws CertificateConversionException {
        try {
            certificatebytearray.close();
        } catch (IOException ioException) {
            throw new CertificateConversionException("Exception while closing the certificate stream", ioException);
        }
    }

    /**
     * This method is used to extract the IssuerName from the certificate
     * 
     * @param certificate
     *            X509 Certificate from which Issuer name need to be read
     * @return Issuer Name extracted from the Certificate
     * @throws CertificateUtilityException
     */
    public static String getIssuerName(final X509Certificate certificate) throws CertificateUtilityException {
        String issuer = null;
        final X500Principal principal = certificate.getIssuerX500Principal();
        final X500Name x500name = new X500Name(principal.getName());
        final RDN commonName = x500name.getRDNs(BCStyle.CN)[0];
        issuer = IETFUtils.valueToString(commonName.getFirst().getValue());
        LOGGER.debug("Extracted Issuer name [{}] from the the given certificate" ,issuer);
        return issuer;
    }

    /**
     * This method is used to extract the Subject Name from the certificate
     * 
     * @param certificate
     *            X509 Certificate from which Subject name need to be read
     * @return Subject Name extracted from the Certificate
     * @throws CertificateUtilityException
     */
    public static String getSubjectName(final X509Certificate certificate) {
        String subject = "";
        final X500Principal principal = certificate.getSubjectX500Principal();
        final X500Name x500name = new X500Name(principal.getName());
        final RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        subject = IETFUtils.valueToString(cn.getFirst().getValue());
        return subject;

    }

    /**
     * This method is used to generate array of CMPCertificates from the list of X509Certificates
     * 
     * @param x509Certificates
     *            List of X509Certificates
     * @return Array of CMPCertificates
     * @throws CertificateEncodingException
     *             This is thrown whenever an error occurs while attempting to encode a certificate
     */
    public static CMPCertificate[] toCMPCertificateArray(final List<X509Certificate> x509Certificates) throws CertificateEncodingException {

        final List<CMPCertificate> cMPCertificateList = new ArrayList<CMPCertificate>();
        CMPCertificate[] cMPCertificates = null;
        if (x509Certificates != null) {
            final Iterator<X509Certificate> itr = x509Certificates.iterator();

            while (itr.hasNext()) {
                cMPCertificateList.add(new CMPCertificate(org.bouncycastle.asn1.x509.Certificate.getInstance(((X509Certificate) itr.next()).getEncoded())));
            }
            final Object[] tempCMPCertificates = cMPCertificateList.toArray();
            cMPCertificates = new CMPCertificate[tempCMPCertificates.length];
            System.arraycopy(tempCMPCertificates, 0, cMPCertificates, 0, tempCMPCertificates.length);
        }

        return cMPCertificates;
    }

    /**
     * Method to map X509Certificate to certificate Object
     * 
     * @param x509Certificate
     *            X509Certificate that need to be mapped
     * @return Certificate Object
     * @throws CertificateParsingException
     *             This is thrown whenever an invalid DER-encoded certificate is parsed or unsupported DER features are found in the Certificate.
     */
    public static Certificate convertX509ToCertificate(final X509Certificate x509Certificate) throws CertificateParsingException {
        final Certificate certificate = new Certificate();
        certificate.setSerialNumber(x509Certificate.getSerialNumber().toString(16));
        certificate.setNotAfter(x509Certificate.getNotAfter());
        certificate.setNotBefore(x509Certificate.getNotBefore());
        certificate.setIssuedTime(x509Certificate.getNotBefore());
        certificate.setX509Certificate(x509Certificate);
        certificate.setSubject(getSubject(x509Certificate.getSubjectX500Principal()));
        certificate.setSubjectAltName(CertificateUtility.getSANFromCertificate(x509Certificate));
        return certificate;
    }

    /**
     * This method is for extracting the subject alternative name from the X509Certificate
     * 
     * @param x509Certificate
     *            Certificate from which SAN is extracted
     * @return Subject Alternative name
     * @throws CertificateParsingException
     *             This is thrown whenever an invalid DER-encoded certificate is parsed or unsupported DER features are found in the Certificate.
     */
    public static SubjectAltName getSANFromCertificate(final X509Certificate x509Certificate) throws CertificateParsingException {
        LOGGER.debug("Extracting subject alternative name from the given certificate");
        Collection<List<?>> subjectAlternativeNames = null;

        SubjectAltName subjectAltName = null;
        subjectAlternativeNames = x509Certificate.getSubjectAlternativeNames();
        if (subjectAlternativeNames != null) {

            final Iterator<List<?>> subjectAltNameIterator = subjectAlternativeNames.iterator();
            final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

            while (subjectAltNameIterator.hasNext()) {
                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                final List subjectAltNameFieldType = (List) subjectAltNameIterator.next();

                final SubjectAltNameFieldType type = getSANFieldType((int) subjectAltNameFieldType.get(0));
                if (type != null) {
                    subjectAltNameField.setType(type);

                    final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
                    subjectAltNameString.setValue(subjectAltNameFieldType.get(1).toString());
                    subjectAltNameField.setValue(subjectAltNameString);
                    subjectAltNameFields.add(subjectAltNameField);
                }
            }

            subjectAltName = new SubjectAltName();
            subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        }
        return subjectAltName;
    }

    private static SubjectAltNameFieldType getSANFieldType(final int sanType) {
        switch (sanType) {
        case GeneralName.rfc822Name:
            return SubjectAltNameFieldType.RFC822_NAME;
        case GeneralName.dNSName:
            return SubjectAltNameFieldType.DNS_NAME;
        case GeneralName.directoryName:
            return SubjectAltNameFieldType.DIRECTORY_NAME;
        case GeneralName.iPAddress:
            return SubjectAltNameFieldType.IP_ADDRESS;
        case GeneralName.registeredID:
            return SubjectAltNameFieldType.REGESTERED_ID;
        case GeneralName.uniformResourceIdentifier:
            return SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER;
        case GeneralName.ediPartyName:
            return SubjectAltNameFieldType.EDI_PARTY_NAME;
        case GeneralName.otherName:
            return SubjectAltNameFieldType.OTHER_NAME;
        default:
            return null;
        }

    }

    /**
     * This method is used to convert X500Principal into Subject Object
     * 
     * @param X500Principal
     *            which has to be converted into X500Principal Object.
     * @return Subject Object
     *
     */

    public static Subject getSubject(final X500Principal principal) {

        final X500Name x500name = new X500Name(principal.getName());
        final Subject subject = new Subject();
        return subject.fromASN1String(x500name.toString());
    }

    /**
     * This method returns Extension Value from x509Certificate of provided attribute.
     * 
     * @param x509Certificate
     *            X509 Certificate from which Extension Value to be read.
     * 
     * @param attributeId
     *            Certificate Attribute ID can be any of subjectAlternativeName, keyUsage, extendedKeyUsage, basicConstraints, subjectKeyIdentifier, authorityInfoAccess and cRLDistributionPoints.
     * 
     * @return extension Value of specific x509Certificate Attribute.
     */
    public static byte[] getAttributeExtensionValue(final X509Certificate x509Certificate, final String attributeId) {
        final byte[] certificateExtensionValue = x509Certificate.getExtensionValue(attributeId);
        return certificateExtensionValue;
    }

    /**
     * This method is used to reverse SubjectDN
     * 
     * @param subjectDN
     *            The subject DN of the certificate.
     * @return reversed SubjectDN
     * @throws InvalidNameException
     *             This is thrown if given DN is not in proper format.
     */

    public static String getReversedSubjectDN(final String subjectDN) throws InvalidNameException {
        final LdapName ldapName = new LdapName(subjectDN);
        final List<Rdn> rdns = ldapName.getRdns();
        final ArrayList<Rdn> rdnsList = new ArrayList<Rdn>(rdns);
        Collections.reverse(rdnsList);
        final LdapName ldapNamenew = new LdapName(rdnsList);
        return ldapNamenew.toString();
    }
}
