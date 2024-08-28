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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.*;

import javax.inject.Inject;
import javax.naming.InvalidNameException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.holder.*;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.AuthorityInformationAccessBuilder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.AuthorityKeyIdentifierBuilder;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy.KeyAccessProviderServiceProxy;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.common.utils.DateUtil;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.builder.IssuingDistributionPointsBuilder;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidAuthorityInformationAccessException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidAuthorityKeyIdentifierException;

/**
 * This class builds the X509 CRL for given {@link CACertificateIdentifier}
 *
 * @author xananer
 *
 */

public class X509CRLBuilder {

    @Inject
    DateUtil dateUtil;

    @Inject
    KeyAccessProviderServiceProxy keyAccessProviderServiceProxy;

    @Inject
    AuthorityKeyIdentifierBuilder authorityKeyIdentifierBuilder;

    @Inject
    IssuingDistributionPointsBuilder issuingDistributionPointsBuilder;

    @Inject
    AuthorityInformationAccessBuilder authorityInformationAccessBuilder;

    @Inject
    CertificatePersistenceHelper persistenceHelper;

    @Inject
    CertificateAuthorityModelMapper authorityModelMapper;

    @Inject
    CertificateModelMapper certificateModelMapper;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    Logger logger;

    @Inject
    SystemRecorder systemRecorder;



    /**
     * This method will build a {@link X509CRL} for a given CertificateAuthority , issuerCertificate , list of revoked certificates and CRLNumber to be provided for the generated CRL.
     *
     * @param certificateAuthority
     *            is the certificate authority for which the CRL has to be generated.
     * @param issuerCertificate
     *            is the issuer certificate for which the CRL has to be generated
     * @param revokedCertificateInfoList
     *            is the list of the revoked certificates
     * @param mappedCrlGenerationInfo
     *            is the associated {@link CrlGenerationInfo} for a certificate authority and certificate
     * @param cRLNumber
     *            is the CRLNumber to be inserted in the generated CRL
     * @return is the X509CRL to be generated for the given input set CertificateAuthority , Issuercertificate , RevokedCertificateList , Associated CRlGenerationInfo and SerialNumber
     * @throws CoreEntityNotFoundException
     *             thrown when given Entity doesn't exists.
     * 
     * @throws CRLGenerationException
     *             is thrown in case of internal error during CRL generation.
     * @throws CRLServiceException
     *             is thrown in case of errors while signing CRL
     * @throws InvalidCRLExtensionException
     *             is thrown in case of Invalid CRL extension found.
     */
    public X509CRL build(final CertificateAuthority certificateAuthority, final Certificate issuerCertificate, final List<RevokedCertificatesInfo> revokedCertificateInfoList,
            final CrlGenerationInfo mappedCrlGenerationInfo, final CRLNumber cRLNumber) throws CoreEntityNotFoundException, CRLGenerationException, CRLServiceException, InvalidCRLExtensionException {

        if (mappedCrlGenerationInfo == null) {
            return null;
        }
        final X509v2CRLBuilderHolder crlBuilder = buildX509v2CRLBuilder(certificateAuthority, mappedCrlGenerationInfo, revokedCertificateInfoList, issuerCertificate, cRLNumber);
        ByteArrayInputStream inputStream = null;
        try {

            final String signatureAlgorithm = mappedCrlGenerationInfo.getSignatureAlgorithm().getName();

            final X500Principal issuerDN = issuerCertificate.getX509Certificate().getSubjectX500Principal();
            logger.info("X500Principal issuerDN in X509CRLBulider class :[{}]", issuerDN);

            final KeyIdentifier keyIdentifier = certificatePersistenceHelper.getKeyIdentifier(certificateAuthority.getName());

            final com.ericsson.oss.itpf.security.kaps.model.holder.X509CRLHolder x509crlHolder = keyAccessProviderServiceProxy.getKeyAccessProviderService().signCRL(keyIdentifier, signatureAlgorithm, crlBuilder, issuerDN);

            final CertificateFactory cf = CertificateFactory.getInstance(Constants.X509);
            inputStream = new ByteArrayInputStream(x509crlHolder.getCrlBytes());
            return  (X509CRL) cf.generateCRL(inputStream);

            } catch (final com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException | com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException
                | com.ericsson.oss.itpf.security.kaps.crl.exception.SignCRLException exception) {

            systemRecorder.recordError(
                    "PKI_CORE_CRL_MANAGEMENT.SIGN_CRL_ERROR",
                    ErrorSeverity.ERROR,
                    "X509CRLBuilder",
                    "Generation of CRL",
                    "Error occured while building X509CRL during the generation of CRL by Certificate of CA " + certificateAuthority.getName() + " with serial number"
                            + issuerCertificate.getSerialNumber() + ".");
            throw new CRLServiceException(ErrorMessages.CRL_GENERATION_EXCEPTION, exception);
        } catch (final com.ericsson.oss.itpf.security.kaps.crl.exception.InvalidCRLExtensionsException invalidCRLExtensionsException) {
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.SIGN_CRL_ERROR", ErrorSeverity.ERROR, "X509CRLBuilder", "Generation of CRL",
                    "Error occured while building X509CRL due to invalid CRL exrtension provided for the CA certificate of CA " + certificateAuthority.getName() + " with serial number "
                            + issuerCertificate.getSerialNumber() + ".");
            logger.error(ErrorMessages.INVALID_CRL_EXTENSIONS + invalidCRLExtensionsException.getMessage());
            throw new CRLGenerationException(ErrorMessages.INVALID_CRL_EXTENSIONS + invalidCRLExtensionsException.getMessage(), invalidCRLExtensionsException);
        } catch (final CertificateException | CRLException exception) {
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.SIGN_CRL_ERROR", ErrorSeverity.ERROR, "X509CRLBuilder", "Generation of CRL",
                    "Error occured while building X509CRL for the CA certificate of CA " + certificateAuthority.getName() + " with serial number " + issuerCertificate.getSerialNumber() + ".");
            throw new CRLGenerationException(ErrorMessages.CRL_GENERATION_EXCEPTION, exception);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException ioException) {
                    logger.debug("Internal error occured while building X509CRL for the CA certificate of CA ", ioException);
                    systemRecorder.recordError(
                            "PKI_CORE_CRL_MANAGEMENT.INTERNAL_ERROR",
                            ErrorSeverity.ERROR,
                            "X509CRLBuilder",
                            "Generation of CRL",
                            "Internal error occured while building X509CRL for the CA certificate of CA " + certificateAuthority.getName() + " with serial number "
                                    + issuerCertificate.getSerialNumber() + ".");
                    // No significance of throw statement here. Commented this as part of Sonar qube issue fixes.
                    // throw new CRLGenerationException(ErrorMessages.CRL_GENERATION_EXCEPTION, ioException);
                }
            }
        }

    }

    /**
     * This method will build the x509CRLHolder for a Certificate Authority , CrlGenerationInfo , List of certificates revoked {@link RevokedCertificatesInfo} , issuerCertificate and serial number of
     * CRL to be generated
     * 
     * @param certificateAuthority
     *            is certificate authority for which the version2 CRL is to be generated
     * @param crlGenerationInfo
     *            is the associated CRL for a CertificateAuthority and the Certificate used for Crl generation
     * @param cRLEntryExtensionHolderList
     *            is the list of the revoked certificates holder {@link RevokedCertificatesInfo}
     * @param issuerCertificate
     *            is the certificate of the CertificateAuthority for which the CRL has to be generated
     * @param serialNumberValue
     *            is the number the serial Number of CRL to be generated
     * 
     * @throws InvalidCRLExtensionException
     *             throws while creating adding CRL Extensions
     * @throws CRLGenerationException
     *             is thrown when DN value is invalid
     * 
     * @return x509v2CRLBuilderHolder is X509v2CRLBuilderHolder Object
     */
    private X509v2CRLBuilderHolder buildX509v2CRLBuilder(final CertificateAuthority certificateAuthority, final CrlGenerationInfo crlGenerationInfo,
            final List<RevokedCertificatesInfo> cRLEntryExtensionHolderList, final Certificate issuerCertificate, final CRLNumber cRLNumber) throws InvalidCRLExtensionException,
            CRLGenerationException {
        final X509v2CRLBuilderHolder x509v2CRLBuilderHolder = new X509v2CRLBuilderHolder();

        Date thisUpdate = dateUtil.getCurrentDate();

        if (crlGenerationInfo.getSkewCrlTime() != null) {
            thisUpdate = dateUtil.subtractDurationFromDate(thisUpdate, crlGenerationInfo.getSkewCrlTime());
        }

        x509v2CRLBuilderHolder.setSubjectDN(issuerCertificate.getX509Certificate().getSubjectX500Principal().toString());
        try {
            final String crlIssuerDn = CertificateUtility.getReversedSubjectDN(issuerCertificate.getX509Certificate().getSubjectX500Principal().toString());

            x509v2CRLBuilderHolder.setSubjectDN(crlIssuerDn);
        } catch (InvalidNameException e) {
            logger.error("Invalid CRL issuer DN while generating CRL" + e.getCause());
            throw new CRLGenerationException("Invalid CRL issuer DN while generating CRL{}", e);
        }

        x509v2CRLBuilderHolder.setThisUpdate(thisUpdate);

        final Date nextUpdate = thisUpdate;
        x509v2CRLBuilderHolder.setNextUpdate(dateUtil.addDurationToDate(nextUpdate, crlGenerationInfo.getValidityPeriod()));

        try {

            final List<CertificateExtensionHolder> extensionHolders = prepareCRLExtensions(certificateAuthority, crlGenerationInfo, issuerCertificate, cRLNumber);
            x509v2CRLBuilderHolder.setExtensionHolders(extensionHolders);

            final ArrayList<RevokedCertificateInfoHolder> revokedCertificatesInfoList = new ArrayList<>();
            for (final RevokedCertificatesInfo cRLEntryExtensionHolder : cRLEntryExtensionHolderList) {
                final String serialNumber = cRLEntryExtensionHolder.getSerialNumber();
                final RevokedCertificateInfoHolder revokedCertificatesInfoHolder = new RevokedCertificateInfoHolder(serialNumber, cRLEntryExtensionHolder.getRevocationDate(),
                        cRLEntryExtensionHolder.getRevocationReason(), cRLEntryExtensionHolder.getInvalidityDate());
                revokedCertificatesInfoList.add(revokedCertificatesInfoHolder);
            }
            x509v2CRLBuilderHolder.setRevokedCertificateInfoHolders(revokedCertificatesInfoList);
        } catch (IOException e) {
            logger.error("Error while creating adding CRL Extensions" + e.getMessage());
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.CRL_GENERATION_FAILURE", ErrorSeverity.ERROR, "X509CRLBuilder", "Generation of CRL",
                    "Error occured while preparing CRL Extensions for the CA certificate of CA " + certificateAuthority.getName() + " with serial number " + issuerCertificate.getSerialNumber() + ".");
            throw new InvalidCRLExtensionException("Error while preparing CRL Extensions" + e.getMessage(), e);
        }
        return x509v2CRLBuilderHolder;
    }

    /**
     * This method will add the CRL extensions to the Version2 CRL
     * 
     * @param certificateAuthority
     *            is the CertificateAuthority for which the CRL has to be generated
     * @param crlGenerationInfo
     *            is the associated CRL for which the CRL has to be generated
     * @param issuerCertificate
     *            is the certificate of CertificateAuthority
     * @param crlBuilder
     *            is the Version2 CRL builder for which the extensions has to be added
     * @throws IOException
     * @throws InvalidCRLExtensionException
     *             throws while creating adding CRL Extensions
     */

    private List<CertificateExtensionHolder> prepareCRLExtensions(final CertificateAuthority certificateAuthority, final CrlGenerationInfo crlGenerationInfo, final Certificate issuerCertificate,
            final CRLNumber cRLNumber) throws IOException, InvalidCRLExtensionException {

        final ArrayList<CertificateExtensionHolder> certificateExtensionHolders = new ArrayList<>();

        final CertificateGenerationInfo certificateGenerationInfo = new CertificateGenerationInfo();

        certificateGenerationInfo.setIssuerCA(certificateAuthority);

        final PublicKey publicKey = issuerCertificate.getX509Certificate().getPublicKey();

        try {

            if (crlGenerationInfo.getCrlExtensions().getAuthorityKeyIdentifier() != null) {
                final Extension authorityKeyIdentifierExtension = authorityKeyIdentifierBuilder.buildAuthorityIdentifier(certificateGenerationInfo, crlGenerationInfo.getCrlExtensions()
                        .getAuthorityKeyIdentifier(), publicKey, issuerCertificate.getSerialNumber());
                final CertificateExtensionHolder certificateExtensionHolder = new CertificateExtensionHolder(authorityKeyIdentifierExtension.getExtnId().getId(),
                        authorityKeyIdentifierExtension.isCritical(), authorityKeyIdentifierExtension.getExtnValue().getOctets());
                certificateExtensionHolders.add(certificateExtensionHolder);
            }

            if (crlGenerationInfo.getCrlExtensions().getCrlNumber() != null) {
                final Extension extensionCRLNumber = new Extension(Extension.cRLNumber, cRLNumber.isCritical(), new DEROctetString(new org.bouncycastle.asn1.x509.CRLNumber(
                        BigInteger.valueOf(cRLNumber.getSerialNumber().intValue()))));
                final CertificateExtensionHolder certificateExtensionHolder = new CertificateExtensionHolder(extensionCRLNumber.getExtnId().getId(), extensionCRLNumber.isCritical(),
                        extensionCRLNumber.getExtnValue().getOctets());
                certificateExtensionHolders.add(certificateExtensionHolder);
            }

            if (crlGenerationInfo.getCrlExtensions().getIssuingDistributionPoint() != null) {
                final Extension issuingDistributionPointExtension = issuingDistributionPointsBuilder.buildIssuingDistributionPoint(crlGenerationInfo);
                final CertificateExtensionHolder certificateExtensionHolder = new CertificateExtensionHolder(issuingDistributionPointExtension.getExtnId().getId(),
                        issuingDistributionPointExtension.isCritical(), issuingDistributionPointExtension.getExtnValue().getOctets());
                certificateExtensionHolders.add(certificateExtensionHolder);
            }

            if (crlGenerationInfo.getCrlExtensions().getAuthorityInformationAccess() != null && crlGenerationInfo.getCrlExtensions().getAuthorityInformationAccess().getAccessDescriptions().size() > 0) {
                final Extension authorityInformationAccessExtension = authorityInformationAccessBuilder.buildAuthorityInformationAccess(crlGenerationInfo.getCrlExtensions()
                        .getAuthorityInformationAccess());
                final CertificateExtensionHolder certificateExtensionHolder = new CertificateExtensionHolder(authorityInformationAccessExtension.getExtnId().getId(),
                        authorityInformationAccessExtension.isCritical(), authorityInformationAccessExtension.getExtnValue().getOctets());
                certificateExtensionHolders.add(certificateExtensionHolder);
            }

        } catch (final InvalidAuthorityKeyIdentifierException | InvalidAuthorityInformationAccessException exception) {
            throw new InvalidCRLExtensionException(ErrorMessages.INVALID_CRL_EXTENSIONS, exception);
        }
        return certificateExtensionHolders;
    }

}