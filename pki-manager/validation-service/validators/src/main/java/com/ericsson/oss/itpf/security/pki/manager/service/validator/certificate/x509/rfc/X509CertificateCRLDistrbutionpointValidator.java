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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc;

import java.io.*;
import java.net.URL;
import java.security.cert.*;
import java.util.Hashtable;
import java.util.Set;

import javax.inject.Inject;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidCRLDistributionPointsExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to validate CRLDistributionPointInfo field of the imported certificate.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateCRLDistrbutionpointValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionUtils certificateExtensionUtils;

    public static final String LDAP_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

    public static final String HTTP = "http://";

    public static final String HTTPS = "https://";

    public static final String FTP = "ftp://";

    public static final String LDAP = "ldap://";

    public static final String X509 = "X.509";

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCRLDistributionPointInfo(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    public void validateCRLDistributionPointInfo(final String caName, final X509Certificate x509Certificate) throws CertificateRevokedException, InvalidCRLDistributionPointsExtension {
        final byte[] octectBytes = x509Certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (octectBytes != null) {
            final Set<String> criticalExtensionOIDs = x509Certificate.getCriticalExtensionOIDs();
            logger.debug("Validating X509Certificate CRLDistributionPointInfo for CA  {} ", caName, "CriticalExtension OIDs are {}", criticalExtensionOIDs);

            isExtensionCritical(criticalExtensionOIDs, caName);

            final DistributionPoint[] distributionPoints = getDistributionPoint(x509Certificate, caName);

            validateDistributionPointFields(distributionPoints, caName);

            validateCRLURI(distributionPoints, caName);

            validateCertificateWithCRL(x509Certificate, distributionPoints, caName);
        }

    }

    private void isExtensionCritical(final Set<String> criticalExtensionOIDs, final String caName) throws InvalidCRLDistributionPointsExtension {

        if (criticalExtensionOIDs.contains(Extension.cRLDistributionPoints.getId())) {
            logger.error("CRLDistributionPointInfo Extension: " + ErrorMessages.EXTENSION_NON_CRITICAL, "for CA {}", caName);
            throw new InvalidCRLDistributionPointsExtension("CRLDistributionPointInfo Extension: " + ErrorMessages.EXTENSION_NON_CRITICAL);
        }

    }

    private DistributionPoint[] getDistributionPoint(final X509Certificate x509Certificate, final String caName) throws InvalidCRLDistributionPointsExtension, MissingMandatoryFieldException {
        CRLDistPoint cRLDistPoint = null;
        final byte[] extensionValue = certificateExtensionUtils.getCertificateAttributeExtensionValue(x509Certificate, Extension.cRLDistributionPoints.getId());

        try {
            final DEROctetString dEROctectString = (DEROctetString) new ASN1InputStream(new ByteArrayInputStream(extensionValue)).readObject();
            cRLDistPoint = CRLDistPoint.getInstance(ASN1Sequence.getInstance(dEROctectString.getOctets()));
        } catch (final IOException iOException) {
            logger.debug("Exception occured while reading input Stream ", iOException);
            logger.error(ErrorMessages.IO_EXCEPTION, " for CA {} ", caName);
            throw new InvalidCRLDistributionPointsExtension(ErrorMessages.IO_EXCEPTION);
        }
        return cRLDistPoint.getDistributionPoints();
    }

    private void validateDistributionPointFields(final DistributionPoint[] distributionPoints, final String caName) {
        if (!checkDistributionPointFields(distributionPoints, caName)) {
            logger.error(ErrorMessages.CRLDISTRIBUTION_POINT_INFO_VALIDATION_FAILED, "for CA {} ", caName);
            throw new InvalidCRLDistributionPointsExtension(ErrorMessages.CRLDISTRIBUTION_POINT_INFO_VALIDATION_FAILED);
        }
    }

    private boolean checkDistributionPointFields(final DistributionPoint[] distributionPoints, final String caName) {
        boolean isCRLIssuerNull = true;
        if (distributionPoints.length == 0) {
            logger.error(ErrorMessages.DISTRIBUTION_POINTS_NULL, " for CA {} ", caName);
            throw new InvalidCRLDistributionPointsExtension(ErrorMessages.DISTRIBUTION_POINTS_NULL);
        }
        for (final DistributionPoint distributionPoint : distributionPoints) {
            if (distributionPoint.getCRLIssuer() == null && distributionPoint.getDistributionPoint() == null) {
                isCRLIssuerNull = false;
            }
        }
        return isCRLIssuerNull;
    }

    private void validateCRLURI(final DistributionPoint[] distributionPoints, final String caName) throws InvalidCRLDistributionPointsExtension {

        final String cRLURI = getCRLURI(distributionPoints);
        if (cRLURI == null) {
            logger.error(ErrorMessages.URI_IS_NULL + "for CA {} ", caName);
            throw new InvalidCRLDistributionPointsExtension(ErrorMessages.URI_IS_NULL);
        }
    }

    private void validateCertificateWithCRL(final X509Certificate x509Certificate, final DistributionPoint[] distributionPoints, final String caName) throws CertificateRevokedException,
            InvalidCRLDistributionPointsExtension {
        final String cRLURI = getCRLURI(distributionPoints);
        if(cRLURI == null){
            logger.error(ErrorMessages.CRL_URI_IS_INVALID, " for CA {} ", caName);
            throw new InvalidCRLDistributionPointsExtension(ErrorMessages.CRL_URI_IS_INVALID);
        }
        final X509CRL x509CRL = downloadCRL(cRLURI, caName);
        if (x509CRL != null) {
            if (x509CRL.isRevoked(x509Certificate)) {
                logger.error(com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages.CERTIFICATE_REVOKED, x509Certificate.getSerialNumber(), "Issuer name is {} "
                        + x509Certificate.getIssuerDN().getName());
                throw new CertificateRevokedException(com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages.CERTIFICATE_REVOKED);
            }
        }

    }

    private String getCRLURI(final DistributionPoint[] distributionPoints) {
        String cRLURI = null;
        for (final DistributionPoint distributionPoint : distributionPoints) {
            final DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
            final GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
            final GeneralName[] names = generalNames.getNames();
            for (final GeneralName generalName : names) {
                if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    DERIA5String.getInstance((ASN1TaggedObject) generalName.toASN1Primitive(), false);
                    cRLURI = DERIA5String.getInstance(generalName.getName()).getString();
                }
            }
        }
        return cRLURI;
    }

    private X509CRL downloadCRL(final String cRLURI, final String caName) throws InvalidCRLDistributionPointsExtension {
        X509CRL x509CRL = null;
        try {
            if (cRLURI.startsWith(HTTP) || cRLURI.startsWith(HTTPS) || cRLURI.startsWith(FTP)) {
                x509CRL = downloadCRLFromWeb(cRLURI);
            } else if (cRLURI.startsWith(LDAP)) {
                x509CRL = downloadCRLFromLDAP(cRLURI, caName);
            } else {
                logger.error(ErrorMessages.CRL_URI_IS_INVALID, " for CA {} ", caName);
                throw new InvalidCRLDistributionPointsExtension(ErrorMessages.CRL_URI_IS_INVALID);
            }
        } catch (final CertificateException | CRLException | IOException | NamingException exception) {
            logger.debug("Error occured while downloading CRL from CRLDistributionPointURI ", exception);
            logger.error(ErrorMessages.FAILED_TO_DOWNLOAD_CRL, " for CA {} ", caName, exception.getMessage());
        }

        return x509CRL;
    }

    private X509CRL downloadCRLFromLDAP(final String ldapURL, final String caName) throws CertificateException, CRLException, InvalidCRLDistributionPointsExtension, NamingException {
        final Hashtable<String, String> ldapMap = new Hashtable<String, String>();
        ldapMap.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_FACTORY);
        ldapMap.put(Context.PROVIDER_URL, ldapURL);

        final DirContext directoryContext = new InitialDirContext(ldapMap);
        final Attributes attributes = directoryContext.getAttributes("");
        final javax.naming.directory.Attribute attributeValues = attributes.get("certificateRevocationList;binary");
        final byte[] attributeByteValue = (byte[]) attributeValues.get();

        if ((attributeByteValue == null) || (attributeByteValue.length == 0)) {
            logger.error(ErrorMessages.FAILED_TO_DOWNLOAD_CRL, " for CA {} ", caName, ldapURL);
            throw new InvalidCRLDistributionPointsExtension(ErrorMessages.FAILED_TO_DOWNLOAD_CRL + ldapURL);
        } else {
            final InputStream inStream = new ByteArrayInputStream(attributeByteValue);
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            final X509CRL crl = (X509CRL) cf.generateCRL(inStream);
            return crl;
        }
    }

    private X509CRL downloadCRLFromWeb(final String cRLURI) throws CertificateException, CRLException, IOException {
        InputStream crlStream = null;
        X509CRL x509CRL = null;
        try {
            final URL url = new URL(cRLURI);
            crlStream = url.openStream();

            final CertificateFactory cf = CertificateFactory.getInstance(X509);
            x509CRL = (X509CRL) cf.generateCRL(crlStream);

        } finally {
            if (crlStream != null) {
                crlStream.close();
            }
        }
        return x509CRL;
    }
}
