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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder;

import java.io.IOException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.xml.datatype.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.util.DateUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.AlgorithmCompatibilityValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * This class builds {@link CertificateGenerationInfoBuilder} object for a given Entity or CAEntity. This will be passed to PKI Core for certificate generation
 *
 */
public class CertificateGenerationInfoBuilder {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    Logger logger;

    @Inject
    private PKIManagerConfigurationListener pkiManagerConfigurationListener;

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    AlgorithmCompatibilityValidator algorithmCompatibilityValidator;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private EntityHelper entityHelper;

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityMapper caEntityMapper;

    // TODO Will be addressed as part of TORF-53891
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Method to build the {@link CertificateGenerationInfo} object from entity
     *
     * @param entity
     *            The entity object
     * @param requestType
     *            The {@link UpdateType}
     * @return CertificateGenerationInfo The CertificateGenerationInfo object
     *
     * @throws InvalidCAException
     *             Realigned the code of cert chain with issuer certificate changes. Thrown in case of issuer CA is not found.
     * @throws InvalidEntityAttributeException
     *             Thrown when the entity has invalid attribute.
     */
    public <T extends AbstractEntity> CertificateGenerationInfo build(final T entity, final RequestType requestType) throws CAEntityNotInternalException, CertificateServiceException,InvalidCAException, InvalidEntityAttributeException {

        logger.debug("Building CertificateGenerationInfo");
        final CertificateGenerationInfo certificateGenerationInfo = new CertificateGenerationInfo();
        final CertificateProfile certificateProfile = entity.getEntityProfile().getCertificateProfile();

        String subjectUniqueIdentifier = null;
        if(certificateProfile.isSubjectUniqueIdentifier() && entity instanceof Entity){
            subjectUniqueIdentifier = entityHelper.getOverridenSubjectUniqueIdentifierValue(entity);
        }
        certificateGenerationInfo.setRequestType(requestType);
        certificateGenerationInfo.setVersion(certificateProfile.getVersion());
        certificateGenerationInfo.setSubjectUniqueIdentifier(certificateProfile.isSubjectUniqueIdentifier());
        certificateGenerationInfo.setSubjectUniqueIdentifierValue(subjectUniqueIdentifier);
        certificateGenerationInfo.setIssuerUniqueIdentifier(certificateProfile.isIssuerUniqueIdentifier());
        if (!isEntityValidityMoreThanIssuer(entity)) {
            certificateGenerationInfo.setSkewCertificateTime(certificateProfile.getSkewCertificateTime());
        } else {
            certificateGenerationInfo.setSkewCertificateTime(null);
        }

        if (entity instanceof CAEntity) {
            final String signatureAlgorithmName = certificateProfile.getSignatureAlgorithm().getName();
            final String keyGenerationAlgorithmName = ((CAEntity) entity).getKeyGenerationAlgorithm().getName();

            algorithmCompatibilityValidator.checkSignatureAndKeyGenerationAlgorithms(signatureAlgorithmName, keyGenerationAlgorithmName);
        }

        certificateGenerationInfo.setSignatureAlgorithm(certificateProfile.getSignatureAlgorithm());

        setEntityInfo(entity, certificateGenerationInfo);
        setIssuerCAAndSignatureAlgorithm(certificateGenerationInfo, certificateProfile);
        setExtensions(entity, certificateGenerationInfo);
        setValidity(entity, certificateGenerationInfo, certificateProfile);

        logger.debug("Returning {}", certificateGenerationInfo);
        return certificateGenerationInfo;
    }

    private <T extends AbstractEntity> void setEntityInfo(final T entity, final CertificateGenerationInfo certificateGenerationInfo) {

        logger.debug("Setting (CA)EntityInfo in CertificateGenerationInfo");

        if (entity instanceof CAEntity) {
            final CertificateAuthority certificateAuthority = ((CAEntity) entity).getCertificateAuthority();
            final SubjectAltName subjectAltName = certificateAuthority.getSubjectAltName();
            if (subjectAltName != null) {
                certificateAuthority.setSubjectAltName(convertIPv6ValidFormat(certificateAuthority.getSubjectAltName()));
            }
            certificateGenerationInfo.setCAEntityInfo(certificateAuthority);
            certificateGenerationInfo.setKeyGenerationAlgorithm(((CAEntity) entity).getKeyGenerationAlgorithm());
        } else {
            final EntityInfo entityInfo = ((Entity) entity).getEntityInfo();
            final SubjectAltName subjectAltName = entityInfo.getSubjectAltName();
            if (subjectAltName != null) {
                entityInfo.setSubjectAltName(convertIPv6ValidFormat(entityInfo.getSubjectAltName()));
            }
            certificateGenerationInfo.setEntityInfo(((Entity) entity).getEntityInfo());
            certificateGenerationInfo.setKeyGenerationAlgorithm(((Entity) entity).getKeyGenerationAlgorithm());
        }
    }

    private <T extends AbstractEntity> void setValidity(final T entity, final CertificateGenerationInfo certificateGenerationInfo, final CertificateProfile certificateProfile)
            throws InvalidEntityAttributeException {

        logger.debug("Setting Validity in CertificateGenerationInfo");

        final Duration skewCertificateTime = certificateProfile.getSkewCertificateTime();

        if (entity instanceof CAEntity) {
            if ((((CAEntity) entity).getCertificateAuthority().isRootCA())) {
                certificateGenerationInfo.setValidity(certificateProfile.getCertificateValidity());
            } else {
                validateSkewCertificateTime(getCertificateValidity(certificateProfile), skewCertificateTime);
                certificateGenerationInfo.setValidity(getCertificateValidity(certificateProfile));
            }
        } else {
            validateSkewCertificateTime(getCertificateValidity(certificateProfile), skewCertificateTime);
            certificateGenerationInfo.setValidity(getCertificateValidity(certificateProfile));
        }
    }

    private static SubjectAltName convertIPv6ValidFormat(final SubjectAltName subjectAltName) {

        for (final SubjectAltNameField subAltNameFiled : subjectAltName.getSubjectAltNameFields()) {
            if (subAltNameFiled.getType() == SubjectAltNameFieldType.IP_ADDRESS) {

                final String givenIpv6 = subAltNameFiled.getValue().toString();
                final String[] splittedIpv6 = givenIpv6.split(":");
                final int octetsCountInSplittedIpv6 = splittedIpv6.length;
                int count = 0;
                for (final String ipv6String : splittedIpv6) {
                    if (ipv6String.equals("")) {
                        count++;
                    }
                }

                final int octectsCountInOriginalIpv6 = 8;
                final int octetsCountInIpv6 = octetsCountInSplittedIpv6 - count;

                StringBuilder zeroOctetsPrepartion = new StringBuilder();
                for (int i = 0; i < octectsCountInOriginalIpv6 - octetsCountInIpv6; i++) {
                    zeroOctetsPrepartion = zeroOctetsPrepartion.append(":0");
                }
                zeroOctetsPrepartion = zeroOctetsPrepartion.append(":");

                String replacedIpv6 = givenIpv6.replaceAll("::", zeroOctetsPrepartion.toString());

                if (replacedIpv6.startsWith(":")) {
                    replacedIpv6 = replacedIpv6.substring(1, replacedIpv6.length());
                } else if (replacedIpv6.endsWith(":")) {
                    replacedIpv6 = replacedIpv6.substring(0, replacedIpv6.length() - 1);
                }
                subAltNameFiled.setValue(getSubjectAltNameString(replacedIpv6));
            }
        }
        return subjectAltName;
    }

    private static AbstractSubjectAltNameFieldValue getSubjectAltNameString(final String value) {
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(value);

        return subjectAltNameString;
    }

    private void setIssuerCAAndSignatureAlgorithm(final CertificateGenerationInfo certificateGenerationInfo, final CertificateProfile certificateProfile) throws CAEntityNotInternalException,CertificateServiceException, InvalidCAException,
            InvalidEntityAttributeException {

        logger.debug("Setting Issuer in CertificateGenerationInfo");
        if (certificateProfile.getIssuer() != null) {

            try{

            if (certificateProfile.getIssuer().getCertificateAuthority().getName() != null) {
                final CAEntityData caEntityData = persistenceManager.findEntityByName(CAEntityData.class, certificateProfile.getIssuer().getCertificateAuthority().getName(), Constants.CA_NAME_PATH);
                if (caEntityData == null) {
                    logger.error("Issuer CA {} not found", certificateProfile.getIssuer().getCertificateAuthority().getName());
                    throw new InvalidCAException(ErrorMessages.ISSUER_CA_NOT_FOUND);
                }
                final CAEntity caEntity = caEntityMapper.toAPIFromModel(caEntityData);
                certificateGenerationInfo.setIssuerSignatureAlgorithm(caEntity.getEntityProfile().getCertificateProfile().getSignatureAlgorithm());
                certificateGenerationInfo.setIssuerCA(caEntity.getCertificateAuthority());
            }

            }catch (PersistenceException e) {
                logger.error("unable to get issuer certificate", e.getMessage());
                throw new CertificateServiceException("unable to get issuer certificate" + e.getMessage(), e);

            }
        } else {
            certificateGenerationInfo.setIssuerSignatureAlgorithm(certificateProfile.getSignatureAlgorithm());
        }
    }

    private <T extends AbstractEntity> void setExtensions(final T entity, final CertificateGenerationInfo certificateGenerateInfo) {

        logger.debug("Setting Extensions in CertificateGenerationInfo");
        final CertificateExtensions certificateExtensions = new CertificateExtensions();

        final List<CertificateExtension> certGenerationInfoCertExtensionList = new ArrayList<CertificateExtension>();

        setExtensionsFromCertProfile(entity, certGenerationInfoCertExtensionList, certificateGenerateInfo);
        setExtensionsFromEntityProfile(entity, certGenerationInfoCertExtensionList);

        certificateExtensions.setCertificateExtensions(certGenerationInfoCertExtensionList);
        certificateGenerateInfo.setCertificateExtensions(certificateExtensions);
    }

    private <T extends AbstractEntity> void setExtensionsFromCertProfile(final T entity, final List<CertificateExtension> certGenerationInfoCertExtensionList,
            final CertificateGenerationInfo certificateGenerationInfo) {

        // TODO Better be using specific classes and abstraction to set
        // generically for such classes, this comment will be implemented as
        // part of TORF-54827

        final List<CertificateExtension> certProfilecertificateExtensionsList = entity.getEntityProfile().getCertificateProfile().getCertificateExtensions().getCertificateExtensions();
        for (final CertificateExtension certificateExtension : certProfilecertificateExtensionsList) {
            if (certificateExtension instanceof SubjectKeyIdentifier || certificateExtension instanceof AuthorityKeyIdentifier || certificateExtension instanceof BasicConstraints
                    || certificateExtension instanceof AuthorityInformationAccess) {
                certGenerationInfoCertExtensionList.add(certificateExtension);
            } else if (certificateExtension instanceof CRLDistributionPoints) {
                if (setCDPSUrl(certificateExtension, certificateGenerationInfo)) {
                    certGenerationInfoCertExtensionList.add(certificateExtension);
                }
            } else if (certificateExtension instanceof SubjectAltName) {
                certGenerationInfoCertExtensionList.add(getSubjectAltNameFromEntity(entity));
            }
        }
    }

    private <T extends AbstractEntity> SubjectAltName getSubjectAltNameFromEntity(final T entity) {

        if (entity.getType() == EntityType.ENTITY) {
            final Entity endEntity = (Entity) entity;
            return endEntity.getEntityInfo().getSubjectAltName();
        } else {
            final CAEntity caEntity = (CAEntity) entity;
            return caEntity.getCertificateAuthority().getSubjectAltName();
        }
    }

    /**
     * This method will replace the values in the CPDS URL with the corresponding values LoadBalancer IP Address , Issuer CA Name and Issuer Certificate Serial Number
     *
     * @param certificateExtension
     * @param issuerCA
     */
    private boolean setCDPSUrl(final CertificateExtension certificateExtension, final CertificateGenerationInfo certificateGenerationInfo) {

        final CRLDistributionPoints cRLDistributionPoints = (CRLDistributionPoints) certificateExtension;
        final List<DistributionPoint> distributionPoints = cRLDistributionPoints.getDistributionPoints();
        Boolean cpdsExtensionFound = false;

        for (final DistributionPoint distributionPoint : distributionPoints) {
            final List<String> fullNames = distributionPoint.getDistributionPointName().getFullName();
            final List<String> fullNamesReplaced = new ArrayList<String>();

            logger.debug("FullNames init are: {} " , fullNames);

            for (String fullName : fullNames) {
                Boolean foundFQDN = false;
                if (certificateGenerationInfo.getIssuerCA() != null) {

                    if (fullName.contains("$FQDN_IPV4")) {

                        if ((pkiManagerConfigurationListener.getCertificatesRevListDistributionPointServiceIpv4Enable() != null)
                                && pkiManagerConfigurationListener.getCertificatesRevListDistributionPointServiceIpv4Enable().equalsIgnoreCase("true")) {

                            if ((pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address() == null) || (pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address().isEmpty())) {

                                this.systemRecorder.recordError("PKI_CERTIFICATE_MANAGEMENT_SERVICE", ErrorSeverity.ERROR, "PKI_CERTIFICATE_MANAGEMENT_SERVICE",
                                        "SbLoadBalancer IPv4 Address is not set for CDPS", null);
                            } else {
                                fullName = fullName.replace("$FQDN_IPV4", pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address() + Constants.COLON_OPERATOR + Constants.CDPS_PORT);

                                logger.info("SbLoadBalancer IPv4 Address setting  for CDPS: {} " , fullName);
                                foundFQDN = true;
                            }

                        }

                    }

                    if (fullName.contains("$FQDN_IPV6")) {

                        if ((pkiManagerConfigurationListener.getCertificatesRevListDistributionPointServiceIpv6Enable() != null)

                        && (pkiManagerConfigurationListener.getCertificatesRevListDistributionPointServiceIpv6Enable().equalsIgnoreCase("true"))) {

                            if ((pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address() == null) || (pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address().isEmpty())) {

                                this.systemRecorder.recordError("PKI_CERTIFICATE_MANAGEMENT_SERVICE", ErrorSeverity.ERROR, "PKI_CERTIFICATE_MANAGEMENT_SERVICE",
                                        "SbLoadBalancer IPv6 Address is not set for CDPS", null);
                            } else {
                                fullName = fullName.replace("$FQDN_IPV6", pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address() + Constants.COLON_OPERATOR + Constants.CDPS_PORT);
                                logger.info("SbLoadBalancer IPv6 Address setting  for CDPS: {} " , fullName);
                                foundFQDN = true;
                            }
                        }

                    }

                    if (fullName.contains("$FQDN_DNS")) {

                        if ((pkiManagerConfigurationListener.getCertificatesRevListDistributionPointServiceDnsEnable() != null)
                                && (pkiManagerConfigurationListener.getCertificatesRevListDistributionPointServiceDnsEnable().equalsIgnoreCase("true"))) {

                            logger.info("Found FQDN_DNS");
                            if ((pkiManagerConfigurationListener.getPublicKeyRegAutorithyPublicServerName() == null)
                                    || (pkiManagerConfigurationListener.getPublicKeyRegAutorithyPublicServerName().isEmpty())
                                    || (pkiManagerConfigurationListener.getPublicKeyRegAutorithyPublicServerName().equalsIgnoreCase("notAssigned"))) {

                                this.systemRecorder.recordError("PKI_CERTIFICATE_MANAGEMENT_SERVICE", ErrorSeverity.ERROR, "PKI_CERTIFICATE_MANAGEMENT_SERVICE",
                                        "PKI RA Server name is not set for CDPS", null);

                            } else {

                                fullName = fullName.replace("$FQDN_DNS", pkiManagerConfigurationListener.getPublicKeyRegAutorithyPublicServerName() + Constants.COLON_OPERATOR + Constants.CDPS_PORT);
                                logger.info("PublicKeyRegAutorithyPublicServerName Setting for CDPS: {} " , fullName);
                                foundFQDN = true;
                            }
                        }

                    }

                    if (foundFQDN) {

                        if (fullName.contains("$CANAME")) {
                            fullName = fullName.replace("$CANAME", certificateGenerationInfo.getIssuerCA().getName());
                        }
                        if (fullName.contains("$CACERTSERIALNUMBER")) {
                            fullName = fullName.replace("$CACERTSERIALNUMBER", certificateGenerationInfo.getIssuerCA().getActiveCertificate().getSerialNumber());
                        }

                        fullNamesReplaced.add(fullName);
                        logger.info("fullName result is: {} " , fullName);
                        cpdsExtensionFound = true;
                    }
                }

                distributionPoint.getDistributionPointName().setFullName(fullNamesReplaced);

            }
        }
        return cpdsExtensionFound;
    }

    private <T extends AbstractEntity> void setExtensionsFromEntityProfile(final T entity, final List<CertificateExtension> certGenerationInfoCertExtensionList) {

        // TODO ExtensionSetter pattern changes will be implemented as part of
        // TORF-54827
        certGenerationInfoCertExtensionList.add(entity.getEntityProfile().getKeyUsageExtension());
        certGenerationInfoCertExtensionList.add(entity.getEntityProfile().getExtendedKeyUsageExtension());
    }

    private Duration getCertificateValidity(final CertificateProfile certificateProfile) throws InvalidEntityAttributeException {

        final List<CertificateData> certificateDatas = caCertificatePersistenceHelper.getCertificateDatas(certificateProfile.getIssuer().getCertificateAuthority().getName(), CertificateStatus.ACTIVE);
        final CertificateData activeCertificate = certificateDatas.get(0);
        final Date issuerCertNotAfterDate = activeCertificate.getNotAfter();

        final Duration entityValidity = certificateProfile.getCertificateValidity();
        final Date entityDate = DateUtility.addDurationToDate(new Date(), entityValidity);

        Duration issuerValidity = null;
        if (entityDate.after(issuerCertNotAfterDate)) {
            try {

                final long durationInMinutes = ((issuerCertNotAfterDate.getTime() - new Date().getTime()) / (1000 * 60));
                final String durationString = "PT" + durationInMinutes + "M";
                issuerValidity = DatatypeFactory.newInstance().newDuration(durationString);

            } catch (final DatatypeConfigurationException datatypeConfigurationException) {
                logger.error("Exception while calculating validity ", datatypeConfigurationException.getMessage());
                throw new InvalidEntityAttributeException("Exception while calculating validity ", datatypeConfigurationException);
            }
            return issuerValidity;
        }
        return entityValidity;
    }

    private void validateSkewCertificateTime(final Duration certificateValidity, final Duration skewCertificateTime) {

        if (skewCertificateTime != null) {
            if (skewCertificateTime.isLongerThan(certificateValidity) || skewCertificateTime.equals(certificateValidity)) {
                throw new CertificateGenerationException("SkewCertificate time can't be greater than or equal to certificate validity");
            }
        }

    }

    private <T extends AbstractEntity> boolean isEntityValidityMoreThanIssuer(final T entity) {

        X509Certificate issuerCertificate = null;
        String issuerName = null;
        final CertificateProfile entityCertificateProfile = entity.getEntityProfile().getCertificateProfile();

        if (entity instanceof CAEntity) {
            final CAEntity caEntity = (CAEntity) entity;
            if (caEntity.getCertificateAuthority().isRootCA()) {
                return false;
            }
        }
        issuerName = entityCertificateProfile.getIssuer().getCertificateAuthority().getName();
        try {

            issuerCertificate = caCertificatePersistenceHelper.getActiveCertificate(issuerName);
        } catch (IOException | java.security.cert.CertificateException | PersistenceException e) {
            logger.error("unable to get issuer's active certificate {}", e.getMessage());
            throw new CertificateServiceException("unable to get issuer's active certificate" + e.getMessage());

        }

        final Date issuerValidity = issuerCertificate.getNotBefore();

        Date entityValidity = DateUtility.getCurrentDate();

        entityValidity = DateUtility.subtractDurationFromDate(entityValidity, entityCertificateProfile.getSkewCertificateTime());
        if (issuerValidity.after(entityValidity)) {
            return true;
        }

        return false;

    }
}
