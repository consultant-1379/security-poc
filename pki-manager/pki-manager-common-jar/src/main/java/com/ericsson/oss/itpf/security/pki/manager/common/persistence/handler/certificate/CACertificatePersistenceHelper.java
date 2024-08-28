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

package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.INTERNAL_ERROR;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.*;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequestStatus;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.*;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.DefaultCertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.CertificateExpiryNotificationDetailsMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExternalCRLMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.certificate.CertificateModelMapperV1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.CertificateUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * Helper class for CRUD operations.
 *
 */
@SuppressWarnings("PMD.ExcessiveClassLength")
public class CACertificatePersistenceHelper {
    @Inject
    Logger logger;

    @Inject
    CertificateModelMapperV1 certificateModelMapperV1;

    @Inject
    CertificateModelMapper certificateModelMapper;

    @Inject
    ExternalCRLMapper crlMapper;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CAEntityDynamicQueryBuilder caEntityDynamicQueryBuilder;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    DefaultCertificateExpiryNotificationDetails defaultCertExpiryNotificationDetails;

    @Inject
    CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

    @Inject
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    private static final String trustProfileQuery = "select t from TrustProfileData t join t.externalCAs c where t.active in(:is_active) and c.id=:externalca_id";
    private static final String fetchAllCaNameAndSerialNumberNativeQuery = "SELECT ca.name, c.serial_number FROM caentity ca JOIN ca_certificate cc ON ca.id = cc.ca_id JOIN certificate c ON cc.certificate_id = c.id where ca.is_external_ca = 'false'";
    private static final String CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS = "select c from CertificateData c where c.id in(select p.id from CAEntityData ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and p.status in(:status) and ec.externalCA = false) ORDER BY c.id DESC";
    private static final String SUBCA_CERTIFICATES_BY_ISSUER_CERTIFICATE_AND_STATUS = "select c from CertificateData c where c.issuerCertificate.id = :issuerCertificate and c.status in(:status) ORDER BY c.id DESC";
    private static final String cANamePath = "certificateAuthorityData.name";
    private static final String queryForExternalCRLByFilter = "select ecrl from ExternalCRLInfoData as ecrl where ecrl.autoUpdate = true and ecrl.nextUpdate < date(:nextUpdateDate) and ecrl.updateUrl is not null and  ecrl.updateUrl != :emptyString";
    private static final String queryForCAEntityDataNotExternalNotAssociated = "select count(*) from caentityassociation where caentityassociation.associatedcaentity_id = :id";
    private static final String queryForFetchLatestCSR = "select cgf from CertificateGenerationInfoData cgf where cgf.forExternalCA = true and cgf.cAEntityInfo in"
            + " ( select ec.id from CAEntityData ec where ec.certificateAuthorityData.name = :name) ORDER BY cgf.id DESC";
    private static final String CA_NAMES_BY_STATUS = "SELECT ca.certificateAuthorityData.name FROM CAEntityData ca WHERE ca.externalCA=false AND ca.certificateAuthorityData.status in (:status)";
    private static final String SUBCA_CERTIFICATES_BY_ISSUER = "select c from CertificateData c where c.issuerCA.id = :issuerCAId";

    /**
     * Store the certificate of entity
     *
     * @param cAName
     *            name of the CA Entity.
     * @param certGenInfo
     *            The CertificateGenerationInfo object.
     * @param certificate
     *            The certificate object to be saved.
     *
     * @throws CertificateEncodingException
     *             Throws in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Throws in the event of corrupted data or an incorrect structure of certificate.
     * @throws PersistenceException
     *             Thrown in case of any problem occurs while doing database operations.
     */
    public void storeCertificate(final String cAName, final CertificateGenerationInfo certGenInfo, final Certificate certificate) throws CertificateEncodingException, IOException,
            PersistenceException {

        final CAEntityData caEntityData = persistenceManager.findEntityByName(CAEntityData.class, cAName, cANamePath);
        final CertificateGenerationInfoData certGenInfoData = persistenceManager.findEntity(CertificateGenerationInfoData.class, certGenInfo.getId());

        storeCertificate(caEntityData, certGenInfoData, certificate);
    }

    /**
     * Store the certificate of the entity
     *
     * @param caEntityData
     *            The CA Entity Data
     * @param certificateGenerationInfoData
     *            Certificate Generation Info Data
     * @param certificate
     *            The certificate object to be saved which contains the X509Certificate and its information.
     * @throws CertificateEncodingException
     *             This is thrown whenever an error occurs while attempting to encode a certificate.
     * @throws PersistenceException
     *             Thrown by the persistence provider when a problem occurs
     */
    public void storeCertificate(final CAEntityData caEntityData, final CertificateGenerationInfoData certificateGenerationInfoData, final Certificate certificate)
            throws CertificateEncodingException, PersistenceException {

        updateActiveCertificateAsInActive(caEntityData);
        final CertificateData certificateData = createCertificateData(certificate);

        certificateGenerationInfoData.setCertificateData(certificateData);
        caEntityData.getCertificateAuthorityData().getCertificateDatas().add(certificateData);
        caEntityData.getCertificateAuthorityData().setStatus(CAStatus.ACTIVE.getId());

        final Set<CrlGenerationInfoData> crlGenerationInfoDataSet = caEntityData.getCertificateAuthorityData().getCrlGenerationInfo();
        for (final CrlGenerationInfoData crlGenerationInfoData : crlGenerationInfoDataSet) {
            crlGenerationInfoData.getCaCertificate().add(certificateData);
        }
        persistenceManager.createEntity(certificateData);
        persistenceManager.updateEntity(certificateGenerationInfoData);
        persistenceManager.refresh(caEntityData);
        persistenceManager.updateEntity(caEntityData);
        systemRecorder.recordSecurityEvent("PKIManager.CertificateManagement", "CACertificatePersistenceHelper", "CA certificate stored for " + caEntityData.getCertificateAuthorityData().getName()
                + "with serial number " + certificateData.getSerialNumber(), "CERTIFICATEMANAGEMENT.STORE_CA_CERTIFICATE_MANAGER_DB", ErrorSeverity.INFORMATIONAL, "SUCCESS");
    }

    private void updateActiveCertificateAsInActive(final CAEntityData caEntityData) throws PersistenceException {

        final List<CertificateData> certificateDatas = getCertificateDatas(caEntityData.getCertificateAuthorityData().getName(), CertificateStatus.ACTIVE);

        if (!ValidationUtils.isNullOrEmpty(certificateDatas)) {
            for (final CertificateData certificateData : certificateDatas) {
                certificateData.setStatus(CertificateStatus.INACTIVE.getId());
                final CAEntityData caEnData = persistenceManager.updateEntity(caEntityData);
                persistenceManager.refresh(caEnData);
            }
        }
    }

    /**
     * Create the certificate Data.
     *
     * @param certificate
     *            The Certificate Object.
     * @return certificateData Object
     * @throws CertificateEncodingException
     *             Throws in case of error occurred while encoding the data.
     */
    private CertificateData createCertificateData(final Certificate certificate) throws CertificateEncodingException {

        final CertificateData certificateData = certificateModelMapper.fromObjectModel(certificate);
        logger.debug("storing certificate of CAEntity whose serial number {}", certificateData.getSerialNumber());
        return certificateData;
    }

    /**
     * Get the certificates of given entity.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @param depth
     *            the amount of information/data required in the the returning object will be provided based on level passed.(LEVEL 0,1,2)
     * @param certificateStatuses
     *            Retrieve the certificates which matches the given statuses.
     * @return List of certificates.
     *
     * @throws CertificateException
     *             Throws in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Throws in the event of corrupted data or an incorrect structure of certificate.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public List<Certificate> getCertificates(final String caEntityName, final MappingDepth depth, final CertificateStatus... certificateStatuses) throws CertificateException, IOException, PersistenceException {

        final List<CertificateData> certificateDatas = getCertificateDatas(caEntityName, certificateStatuses);

        if (ValidationUtils.isNullOrEmpty(certificateDatas)) {
            return null;
        }
        return certificateModelMapperV1.toApi(certificateDatas, depth);

    }

    /**
     * Get the certificate data list of given entity.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @param certificateStatuses
     *            Retrieve the certificates which matches the given statuses.
     * @return List of certificate data objects.
     *
     */
    public List<CertificateData> getCertificateDatas(final String caEntityName, final CertificateStatus... certificateStatuses) {
        final List<Integer> certificateStatusIds = new ArrayList<Integer>();
        for (final CertificateStatus certificateStatus : certificateStatuses) {
            certificateStatusIds.add(certificateStatus.getId());
        }

        final Query query = persistenceManager.getEntityManager().createQuery(CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS);
        query.setParameter("name", caEntityName);
        query.setParameter("status", certificateStatusIds);

        final List<CertificateData> certificateDatas = query.getResultList();
        if (ValidationUtils.isNullOrEmpty(certificateDatas)) {
            return null;
        }

        return certificateDatas;

    }

    /**
     * This method gets all certificates which are issued by given certificate and which are not revoked and expired.
     *
     * @param issuerCertificate
     *            certificate using which all its children are fetched.
     * @return list of certificates which got issued by given certificate.
     * @throws PersistenceException
     */
    public List<CertificateData> getActiveInActiveCertificateDatas(final Certificate issuerCertificate) throws PersistenceException {

        final List<Integer> certificateStatusIds = new ArrayList<Integer>();
        certificateStatusIds.add(CertificateStatus.ACTIVE.getId());
        certificateStatusIds.add(CertificateStatus.INACTIVE.getId());

        final Query query = persistenceManager.getEntityManager().createQuery(SUBCA_CERTIFICATES_BY_ISSUER_CERTIFICATE_AND_STATUS);
        query.setParameter("issuerCertificate", issuerCertificate.getId());
        query.setParameter("status", certificateStatusIds);

        final List<CertificateData> certificateDatas = query.getResultList();
        if (ValidationUtils.isNullOrEmpty(certificateDatas)) {
            return null;
        }
        return certificateDatas;
    }

    /**
     * Get active certificate of given entity.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @return X509Certificate. returns X509Certificate equivalent
     *
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     * @throws IOException
     *             Signals that an I/O exception of some sort has occurred
     * @throws CertificateException
     *             thrown indicating one of a variety of certificate problems
     */
    public X509Certificate getActiveCertificate(final String caEntityName) throws CertificateException, IOException, PersistenceException {

        final List<CertificateData> certificateDatas = getCertificateDatas(caEntityName, CertificateStatus.ACTIVE);

        if (ValidationUtils.isNullOrEmpty(certificateDatas)) {
            return null;
        }

        final CertificateData activeCertificate = certificateDatas.get(0);
        final X509Certificate x509Certificate = CertificateUtils.convert(activeCertificate.getCertificate());

        return x509Certificate;
    }

    /**
     * This method will return a list of CACertificateIdentifier objects. Each CACertificateIdentifier object will be prepared by the fetched CA certificate
     *
     * @return List<CACertificateIdentifier>
     */
    public List<CACertificateIdentifier> getAllCANameAndSerialNumber() {
        final List<CACertificateIdentifier> caCertificateIdentifierList = new ArrayList<CACertificateIdentifier>();
        final Query query = persistenceManager.getEntityManager().createNativeQuery(fetchAllCaNameAndSerialNumberNativeQuery);
        final List<Object[]> resultSet = query.getResultList();
        if (!resultSet.isEmpty()) {
            for (final Object[] result : resultSet) {

                final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
                caCertificateIdentifier.setCaName((String) result[0]);
                caCertificateIdentifier.setCerficateSerialNumber((String) result[1]);
                caCertificateIdentifierList.add(caCertificateIdentifier);

            }
            return caCertificateIdentifierList;
        }
        return null;
    }

    /**
     * Get CAEntityData of given CAEntity.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @return caEntityData
     * @throws CANotFoundException
     *             Throws in case of CAEntity not found in the database.
     * @throws EntityServiceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public CAEntityData getCAEntity(final String caEntityName) throws CANotFoundException, EntityServiceException {

        CAEntityData caEntityData = null;

        try {
            caEntityData = persistenceManager.findEntityByName(CAEntityData.class, caEntityName, Constants.CA_NAME_PATH);

        } catch (final PersistenceException persistenceException) {
            logger.error(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_ENTITY + persistenceException);
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_ENTITY, persistenceException);
        }

        if (caEntityData == null) {
            logger.error("CAEntity {}  not found", caEntityName);
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + ": " + caEntityName);
        }
        return caEntityData;

    }

    /**
     * This method is used to get CAEntityData information for the given CAEntity.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @param subjectNamePath
     *            subjectDn
     * @return caEntityData
     * @throws CANotFoundException
     *             Throws in case of CAEntity not found in the database.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public CAEntityData getCAEntity(final String caEntityName, final String subjectNamePath) throws CANotFoundException, PersistenceException {

        final CAEntityData caEntityData = persistenceManager.findEntityByName(CAEntityData.class, caEntityName, subjectNamePath);

        if (caEntityData == null) {
            logger.error("CAEntity {}  not found", caEntityName);
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + ": " + caEntityName);
        }
        return caEntityData;

    }

    public Certificate getExternalCACertificate(final String caEntityName, final String serialNumber) throws PersistenceException, CertificateException, IOException {

        final Query query = persistenceManager.getEntityManager().createQuery(
                "select c from CertificateData c where c.serialNumber =:serialnumber and c.id in(select p.id from CAEntityData"
                        + " ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true)");
        query.setParameter("name", caEntityName);
        query.setParameter("serialnumber", serialNumber);

        final List<CertificateData> certificateDatas = query.getResultList();
        if (!certificateDatas.isEmpty()) {
            List<Certificate> certificates;
            certificates = certificateModelMapper.toObjectModel(certificateDatas);
            return (certificates.get(0));
        } else {
            return null;
        }
    }

    /**
     * Get CAEntityData of given CAEntity Name and/or Serial Number.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @param serialNumber
     *            serial Number of certificate
     * @return caEntityData {@link CAEntityData}
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public CAEntityData getCAEntityData(final String caEntityName, final String serialNumber) throws PersistenceException {

        final StringBuilder queryStringBuilder = new StringBuilder();
        queryStringBuilder.append(" select ec from CAEntityData ec ");

        if (serialNumber != null) {
            queryStringBuilder.append(" inner join ec.certificateAuthorityData.certificateDatas certs  ");
        }
        queryStringBuilder.append(" WHERE ");

        if (caEntityName != null && serialNumber != null) {
            queryStringBuilder.append(" ec.certificateAuthorityData.name = :name AND certs.serialNumber = :serialnumber ");
        } else if (caEntityName != null) {
            queryStringBuilder.append(" ec.certificateAuthorityData.name = :name ");
        } else if (serialNumber != null) {
            queryStringBuilder.append(" certs.serialNumber = :serialnumber ");
        } else {
            return null;
        }

        final Query query = persistenceManager.getEntityManager().createQuery(queryStringBuilder.toString());
        if (caEntityName != null) {
            query.setParameter("name", caEntityName);
        }
        if (serialNumber != null) {
            query.setParameter("serialnumber", serialNumber);
        }

        final List<CAEntityData> cAEntityDatas = query.getResultList();
        if (!cAEntityDatas.isEmpty()) {
            return (cAEntityDatas.get(0));
        } else {
            return null;
        }

    }

    /**
     * Get CAEntityData of given CAEntity subjectDN,issuerDN and Serial Number.
     *
     * @param dnBasedCertIdentifier
     *            contains subjectDn,issuerDn and serialNumber.
     *
     * @return CA Entities Count
     *
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public Long getCAEntitiesCount(final DNBasedCertificateIdentifier dNBasedIdentifier) throws PersistenceException {
        final StringBuilder dynamicQuery = new StringBuilder();

        dynamicQuery.append(" select count(*) from CAEntityData ced ");

        if (dNBasedIdentifier.getIssuerDN() != null) {
            dynamicQuery.append(" inner join ced.certificateAuthorityData.issuer iced ");
        }
        if (dNBasedIdentifier.getCerficateSerialNumber() != null) {
            dynamicQuery.append(" inner join ced.certificateAuthorityData.certificateDatas certs ");
        }
        final Map<String, Object> parameters = caEntityDynamicQueryBuilder.where(dNBasedIdentifier, dynamicQuery);

        final Long cAEntitiesCount = persistenceManager.findEntitiesCountByAttributes(dynamicQuery.toString(), parameters);

        return cAEntitiesCount;
    }

    /**
     * Store the CertificateGenerationInfo object.
     *
     * @param certificateGenerationInfo
     *            The CertificateGenerateInfo object.
     * @throws CertificateServiceException
     *             Thrown in case any database issue occurs.
     */

    public void storeCertificateGenerateInfo(final CertificateGenerationInfo certificateGenerationInfo) throws CertificateServiceException {
        try {
            final CertificateGenerationInfoData certificateGenerationInfoData = certificateModelMapper.toCertificateGenerationInfoData(certificateGenerationInfo);
            persistenceManager.createEntity(certificateGenerationInfoData);
            certificateGenerationInfo.setId(certificateGenerationInfoData.getId());
        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE, persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + persistenceException);
        }
    }

    /**
     * Updates {@link CertificateGenerationInfoData} with {@link CertificateRequestData}
     *
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} to be persisted in the database
     * @param certificateRequest
     *            {@link CertificateRequestData} to be saved in the database.
     *
     * @throws CertificateServiceException
     *             Thrown in case any database issue occurs.
     */
    public void updateCertificateGenerateInfoWithCSR(final CertificateGenerationInfo certificateGenerationInfo, final byte[] certificateRequest) throws CertificateServiceException {

        try {
            final CertificateGenerationInfoData certificateGenerationInfoData = persistenceManager.findEntity(CertificateGenerationInfoData.class, certificateGenerationInfo.getId());

            final CertificateRequestData certificateRequestData = new CertificateRequestData();

            certificateRequestData.setCsr(certificateRequest);
            certificateRequestData.setStatus(CertificateRequestStatus.NEW.getId());
            certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);
            persistenceManager.updateEntity(certificateGenerationInfoData);
        } catch (final PersistenceException persistenceException) {
            logger.error(INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(INTERNAL_ERROR + persistenceException);
        }
    }

    /**
     * Store the certificate of External CA
     *
     * @param extCAName
     *            The External CA name.
     * @param certificate
     *            The certificate object to be saved.
     * @param isChainRequired
     *            is true if user has to import Certificates in order
     *
     * @throws CANotFoundException
     *             is thrown if ca is not found in the database.
     * @throws CertificateFieldException
     *             is thrown if any error occurs while encoding certificate.
     * @throws CertificateNotFoundException
     *             Thrown when external ca certificate is not found in database.
     * @throws ExternalCAAlreadyExistsException
     *             Throws in case of given external CA already exists.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public void storeExtCACertificate(final String extCAName, final Certificate certificate, final boolean isChainRequired) throws CANotFoundException, CertificateFieldException,
            CertificateNotFoundException, ExternalCAAlreadyExistsException, PersistenceException {

        CAEntityData caEntityData = getCaEntityData(extCAName, certificate.getX509Certificate().getSubjectDN().getName());
        final Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails = defaultCertExpiryNotificationDetails.prepareDefaultCertificateExpiryNotificationDetails();
        if (caEntityData == null) {
            caEntityData = createCAEntityData(extCAName, certificate.getX509Certificate(), certificateExpiryNotificationDetails);
        } else {
            caEntityData.getCertificateExpiryNotificationDetailsData().addAll(
                    certExpiryNotificationDetailsMapper.fromAPIToModel(certificateExpiryNotificationDetails, Constants.EXTERNAL_CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE));
            SubjectAltName subjAltName;
            try {
                subjAltName = CertificateUtility.getSANFromCertificate(certificate.getX509Certificate());
                caEntityData.getCertificateAuthorityData().setSubjectAltName(fromSubjectAltName(subjAltName));
            } catch (final CertificateParsingException e) {
                logger.error(INTERNAL_ERROR, e.getMessage());
                throw new CertificateFieldException(ErrorMessages.CERTIFICATE_ENCODING_FAILED, e);
            }
        }
        final Set<CertificateData> certificateDatas = caEntityData.getCertificateAuthorityData().getCertificateDatas();
        for (final CertificateData certData : certificateDatas) {
            certData.setStatus(CertificateStatus.INACTIVE.getId());
        }

        storeCertificateAndCAEntityData(caEntityData, certificate, isChainRequired);
    }

    /**
     * This method is used to store Certificate and CAEntityData.
     *
     * @param certificate
     *            The certificate object to be saved.
     * @param caEntityData
     *            the CA Entity Data object to be updated.
     *
     * @throws CANotFoundException
     *             is thrown if ca is not found in the database.
     * @throws CertificateFieldException
     *             is thrown if any error occurs while encoding certificate.
     * @throws CertificateNotFoundException
     *             Thrown when external ca certificate is not found in database.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    private void storeCertificateAndCAEntityData(final CAEntityData caEntityData, final Certificate certificate, final boolean isChainRequired) throws CANotFoundException, CertificateFieldException,
            CertificateNotFoundException, PersistenceException {
        final CertificateData certificateData;
        try {
            certificateData = certificateModelMapper.fromObjectModel(certificate);

            extCACertificatePersistanceHandler.setIssuerToExtCertificate(caEntityData, certificateData, isChainRequired);

        } catch (final CertificateEncodingException certificateEncodingException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException.getMessage());
            throw new CertificateFieldException(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException);
        }

        storeCertificate(caEntityData, certificateData);
    }

    private void storeCertificate(final CAEntityData caEntityData, final CertificateData certificateData) throws PersistenceException {
        logger.debug("storing certificate of CAEntity {}", certificateData);

        persistenceManager.createEntity(certificateData);

        final Set<CertificateData> certList = new HashSet<CertificateData>();
        certList.addAll(caEntityData.getCertificateAuthorityData().getCertificateDatas());
        certList.add(certificateData);
        caEntityData.getCertificateAuthorityData().setCertificateDatas(certList);
        caEntityData.getCertificateAuthorityData().setStatus(CAStatus.ACTIVE.getId());
        persistenceManager.updateEntity(caEntityData);
    }

    /**
     * Get the CAEntityData of given External CA Name.
     *
     * @param extCAName
     *            The External CA name.
     * @param subjectDN
     *            The Subject DN.
     * @throws ExternalCAAlreadyExistsException
     *             Thrown when the external CA already present in the system.
     * @throws PersistenceException
     *             Thrown when internal error occurs in the system.
     */
    private CAEntityData getCaEntityData(final String extCAName, final String subjectDN) throws ExternalCAAlreadyExistsException, PersistenceException {
        final String CA_NAME_PATH = "certificateAuthorityData.name";

        CAEntityData externalCAData = null;
        final CAEntityData caEntityData = persistenceManager.findEntityByName(CAEntityData.class, extCAName, CA_NAME_PATH);
        if (caEntityData != null && !caEntityData.isExternalCA()) {
            throw new ExternalCAAlreadyExistsException(ErrorMessages.EXTERNAL_CA_NAME_USED_FOR_INTERNAL);
        } else if (caEntityData != null) {
            externalCAData = caEntityData; // TODO DespicableUs check subject DN
                                           // equality without using string
                                           // comparison
            if (!externalCAData.getCertificateAuthorityData().getSubjectDN().equals(subjectDN)) {
                throw (new ExternalCAAlreadyExistsException(ErrorMessages.CERTIFICATE_WITH_DIFFERENT_SUBJECTDN)); // TODO
                // DespicableUs
                // use a more
                // appropriate
                // exception
            }
        }
        return externalCAData;
    }

    /**
     * Get the certificates of given External CA entity.
     *
     * @param extCAName
     *            The External CA name.
     * @param certificateStatuses
     *            Retrieve the certificates which matches the given statuses.
     * @return List of certificates.
     *
     * @throws CertificateException
     *             Throws in the event of not able to build the certificate from byte array.
     * @throws IOException
     *             Throws in the event of corrupted data or an incorrect structure of certificate.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public List<Certificate> getCertificatesForExtCA(final String extCAName, final CertificateStatus... certificateStatuses) throws CertificateException, IOException, PersistenceException {

        final List<Integer> certificateStatusIds = new ArrayList<Integer>();
        for (final CertificateStatus certificateStatus : certificateStatuses) {
            certificateStatusIds.add(certificateStatus.getId());
        }

        final Query query = persistenceManager.getEntityManager().createQuery(
                "select c from CertificateData c where c.status in(:status) and c.id in(select p.id from CAEntityData"
                        + " ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true)");
        query.setParameter("name", extCAName);
        query.setParameter("status", certificateStatusIds);

        final List<CertificateData> certificateDatas = query.getResultList();
        if (!certificateDatas.isEmpty()) {
            return certificateModelMapper.toObjectModel(certificateDatas);
        } else {
            return null;
        }
    }

    /**
     * Create CAEntityData of given External CA Name and certificate.
     *
     * @param extCAName
     *            The External CA name.
     * @param x509Certificate
     *            The x509Certificate.
     * @param certificateExpiryNotificationDetails
     *            Default Certificate Expiry Notification Details for External Ca.
     * @return The CA Entity Data object
     *
     * @throws CertificateFieldException
     * @throws PersistenceException
     */
    public CAEntityData createCAEntityData(final String extCAName, final X509Certificate x509Certificate, final Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails)
            throws CertificateFieldException, PersistenceException {
        final CAEntityData externalCAData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        final Set<CertificateData> certificatesData = new HashSet<CertificateData>();
        certificateAuthorityData.setCertificateDatas(certificatesData);
        certificateAuthorityData.setExternalCrlInfoData(null);

        certificateAuthorityData.setName(extCAName);
        if (x509Certificate.getIssuerDN().equals(x509Certificate.getSubjectDN())) {
            certificateAuthorityData.setRootCA(true);
        } else {
            certificateAuthorityData.setRootCA(false);
        }
        try {
            if (x509Certificate.getSubjectAlternativeNames() != null && x509Certificate.getSubjectAlternativeNames().size() > 0) {
                final SubjectAltName subjAltName = CertificateUtility.getSANFromCertificate(x509Certificate);
                certificateAuthorityData.setSubjectAltName(fromSubjectAltName(subjAltName));
            }
        } catch (final CertificateParsingException e) {
            throw new CertificateFieldException(ErrorMessages.CERTIFICATE_ENCODING_FAILED, e);
        }
        if (x509Certificate.getSubjectDN() != null) {
            certificateAuthorityData.setSubjectDN(x509Certificate.getSubjectDN().getName());
        }
        certificateAuthorityData.setStatus(CAStatus.ACTIVE.getId());
        certificateAuthorityData.setIssuer(null);
        certificateAuthorityData.setExternalCrlInfoData(null);
        externalCAData.setPublishCertificatetoTDPS(true);
        externalCAData.setCertificateAuthorityData(certificateAuthorityData);
        externalCAData.setExternalCA(true);
        externalCAData.setKeyGenerationAlgorithm(null);
        externalCAData.setCertificateExpiryNotificationDetailsData(certExpiryNotificationDetailsMapper.fromAPIToModel(certificateExpiryNotificationDetails,
                Constants.EXTERNAL_CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE));

        persistenceManager.createEntity(externalCAData);
        return externalCAData;
    }

    /**
     * Create CAEntityData of given External CA Name and CRL.
     *
     * @param extCAName
     *            The External CA name.
     *
     * @param crl
     *            The CRL.
     *
     * @return The CA Entity Data object
     * @throws ExternalCRLEncodedException
     */

    private CAEntityData createAssociatedCAEntityData(final String extCAName, final ExternalCRLInfo crl) throws ExternalCRLEncodedException, PersistenceException {
        final CAEntityData externalCAData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        final Set<CertificateData> certificatesData = new HashSet<CertificateData>();

        certificateAuthorityData.setCertificateDatas(certificatesData);
        certificateAuthorityData.setName(extCAName);
        certificateAuthorityData.setRootCA(false);
        certificateAuthorityData.setSubjectDN(crl.getX509CRL().retrieveCRL().getIssuerDN().getName());
        certificateAuthorityData.setStatus(CAStatus.NEW.getId());
        certificateAuthorityData.setIssuer(null);

        final ExternalCRLInfoData externalCrlInfoData = crlMapper.fromAPIToModel(crl);
        persistenceManager.createEntity(externalCrlInfoData);
        certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);

        externalCAData.setCertificateAuthorityData(certificateAuthorityData);
        externalCAData.setPublishCertificatetoTDPS(true);
        externalCAData.setExternalCA(true);
        externalCAData.setKeyGenerationAlgorithm(null);

        persistenceManager.createEntity(externalCAData);
        return externalCAData;
    }

    /**
     * Add CRL of given External CA Name.
     *
     * @param extCAName
     *            The External CA name.
     *
     * @param crl
     *            The CRL.
     *
     */
    public void addCRL(final String extCAName, final ExternalCRLInfo crl) throws ExternalCANotFoundException, ExternalCRLEncodedException, ExternalCRLException, PersistenceException {
        if (crl.getX509CRL() == null) {
            throw new ExternalCRLEncodedException(ErrorMessages.EXTERNAL_CA_CRL_EMPTY);
        }

        final CAEntityData caEntityData = getAndCheckCAEntity(extCAName);
        final X500Name issuerDN = new X500Name(crl.getX509CRL().retrieveCRL().getIssuerDN().getName());
        final X500Name subjectDN = new X500Name(caEntityData.getCertificateAuthorityData().getSubjectDN());

        // Subject of Certificate (subjectDN) = subject CRL (issuerDN)
        setCrlConfigParams(crl, caEntityData);
        if (subjectDN.equals(issuerDN)) {
            // ROOT CA
            addOrUpdateCRLOnCAEntityData(crl, caEntityData);
        } else { // Subject of Certificate != subject CRL; check on all
                 // associated

            final Set<CAEntityData> associated = caEntityData.getAssociated();
            for (final CAEntityData subExtCA : associated) {
                final X500Name subCASubjectDN = new X500Name(subExtCA.getCertificateAuthorityData().getSubjectDN());
                if (subCASubjectDN.equals(issuerDN)) {
                    addOrUpdateCRLOnCAEntityData(crl, subExtCA);
                    return;
                }
            }
            // otherwise create a CAEntity (associated) and the ExternalCrlInfo
            final String number = String.valueOf(caEntityData.getAssociated().size() + 1);
            final String subjectCNCRL = getCN(crl.getX509CRL().retrieveCRL().getIssuerDN().getName());
            final String nameSubCA = extCAName + "_" + number + "_" + subjectCNCRL;

            final CAEntityData subExtCAEntityData = createAssociatedCAEntityData(nameSubCA, crl);
            persistenceManager.createEntity(subExtCAEntityData);
            associated.add(subExtCAEntityData);
            persistenceManager.updateEntity(caEntityData);
        }
    }

    public void configCRLInfo(final String extCAName, final Boolean isCrlAutoUpdateEnabled, final Integer crlAutoUpdateTimer) throws ExternalCANotFoundException, PersistenceException {
        final CAEntityData caEntityData = getAndCheckCAEntity(extCAName);

        final ExternalCRLInfoData crlRoot = caEntityData.getCertificateAuthorityData().getExternalCrlInfoData();

        // ROOT of crl
        if (crlRoot == null) {
            setCRLParameters(isCrlAutoUpdateEnabled, crlAutoUpdateTimer, caEntityData, null);
        } else {
            setCRLParameters(isCrlAutoUpdateEnabled, crlAutoUpdateTimer, caEntityData, crlRoot);
            persistenceManager.updateEntity(crlRoot);
        }
    }

    /**
     * @param isCrlAutoUpdateEnabled
     * @param crlAutoUpdateTimer
     * @param caEntityData
     * @param crl
     */
    private void setCRLParameters(final Boolean isCrlAutoUpdateEnabled, final Integer crlAutoUpdateTimer, final CAEntityData caEntityData, ExternalCRLInfoData crl) throws PersistenceException {
        if (crl == null) {
            crl = new ExternalCRLInfoData();
        }
        crl.setAutoUpdate(isCrlAutoUpdateEnabled);
        crl.setAutoUpdateCheckTimer(crlAutoUpdateTimer);
        setCrlNextUpdate(crl);
        propagateForAllAssociated(caEntityData, crl);
    }

    /**
     * @param crlRoot
     */
    private void propagateForAllAssociated(final CAEntityData caEntityRootData, final ExternalCRLInfoData crlRoot) throws PersistenceException {
        final Set<CAEntityData> associated = caEntityRootData.getAssociated();
        for (final CAEntityData subExtCA : associated) {
            final ExternalCRLInfoData crlSubCA = subExtCA.getCertificateAuthorityData().getExternalCrlInfoData();
            if (crlSubCA != null) {
                crlSubCA.setAutoUpdate(crlRoot.isAutoUpdate());
                crlSubCA.setAutoUpdateCheckTimer(crlRoot.getAutoUpdateCheckTimer());
                setCrlNextUpdate(crlSubCA);
                persistenceManager.updateEntity(crlSubCA);
            }
        }
    }

    /**
     * @param caEntityData
     */
    public CAEntityData getAndCheckCAEntity(final String extCAName) throws ExternalCANotFoundException, PersistenceException {
        final CAEntityData caEntityData = persistenceManager.findEntityByName(CAEntityData.class, extCAName, "certificateAuthorityData.name");

        if (caEntityData == null || caEntityData.getCertificateAuthorityData() == null) {
            logger.error(ErrorMessages.EXTERNAL_CA_NOT_FOUND);
            throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NOT_FOUND);
        } else if (!caEntityData.isExternalCA()) {
            logger.error(ErrorMessages.EXTERNAL_CA_NAME_USED_FOR_INTERNAL);
            throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NAME_USED_FOR_INTERNAL);
        }
        try {
            final Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("id", caEntityData.getId());
            final BigInteger count = (BigInteger) persistenceManager.findEntityCountByNativeQuery(queryForCAEntityDataNotExternalNotAssociated, parameters);
            if (count != null && count.intValue() > 0) {
                logger.error(ErrorMessages.EXTERNAL_CA_NOT_FOUND);
                throw new ExternalCANotFoundException("This is a subCA of an ExternalCA ");
            }
        } catch (final PersistenceException exception) {
            throw exception;
        }
        return caEntityData;
    }

    /**
     * @param ExternalCRLInfoData
     */
    private void setCrlNextUpdate(final ExternalCRLInfoData crl) throws PersistenceException {
        if (crl.getUpdateUrl() != null && !crl.getUpdateUrl().isEmpty()) {
            if (crl.isAutoUpdate() && crl.getAutoUpdateCheckTimer() > 0) {
                final Calendar c = Calendar.getInstance();
                final Date currentTime = new Date();
                c.setTime(currentTime); // sets current time
                c.add(Calendar.DATE, crl.getAutoUpdateCheckTimer());
                crl.setNextUpdate(c.getTime());
            } else {
                // reset nextUpdate value from crl
                if (crl.getCrl() != null) {
                    X509CRLHolder x509CrlHolder;
                    try {
                        x509CrlHolder = new X509CRLHolder(crl.getCrl());
                        crl.setNextUpdate(x509CrlHolder.retrieveCRL().getNextUpdate());
                    } catch (final CRLException | IOException e) {
                        throw new PersistenceException(e);
                    }
                }
            }
        }
        if (crl.getNextUpdate() == null) {
            crl.setNextUpdate(new Date(0));
        }
    }

    /**
     * @param ExternalCRLInfo
     */
    private void setCrlNextUpdate(final ExternalCRLInfo crl) {
        if (crl.getUpdateURL() != null && !crl.getUpdateURL().isEmpty()) {
            if (crl.isAutoUpdate() && crl.getAutoUpdateCheckTimer() > 0) {
                final Calendar c = Calendar.getInstance();
                final Date currentTime = new Date();
                c.setTime(currentTime); // sets current time
                c.add(Calendar.DATE, crl.getAutoUpdateCheckTimer());
                crl.setNextUpdate(c.getTime());
            } else {
                // reset nextUpdate value from crl
                if (crl.getX509CRL() != null) {
                    crl.setNextUpdate(crl.getX509CRL().retrieveCRL().getNextUpdate());
                }
            }
        }
        if (crl.getNextUpdate() == null) {
            crl.setNextUpdate(new Date(0));
        }
    }

    private static String getCN(final String dnWithCn) {
        if (dnWithCn.contains(",")) {
            final String[] str = SubjectUtils.splitDNs(dnWithCn);
            for (int i = 0; i < str.length - 1; i++) {
                if (str[i].contains("=")) {
                    final String[] istr = str[i].split("=");
                    if (istr[0].contains("CN") || istr[0].contains("cn")) {
                        return istr[1];
                    }
                }
            }

        } else if (dnWithCn.contains("=")) {
            final String[] istr = dnWithCn.split("=");
            if (istr[0].contains("CN") || istr[0].contains("cn")) {
                return istr[1];
            }
        }
        return dnWithCn;
    }

    /**
     * Add or Update CRL in CA Entity Data object.
     *
     * @param crl
     *            The CRL
     *
     * @param caEntityData
     *            The CA Entity Data object
     *
     */

    private void addOrUpdateCRLOnCAEntityData(final ExternalCRLInfo crl, final CAEntityData caEntityData) throws ExternalCRLException, PersistenceException {

        final ExternalCRLInfoData currentCrl = caEntityData.getCertificateAuthorityData().getExternalCrlInfoData();
        if (currentCrl == null) {
            final ExternalCRLInfoData externalCrlInfoData = crlMapper.fromAPIToModel(crl);
            persistenceManager.createEntity(externalCrlInfoData);
            caEntityData.getCertificateAuthorityData().setExternalCrlInfoData(externalCrlInfoData);
            persistenceManager.updateEntity(caEntityData);
        } else {
            currentCrl.setAutoUpdate(crl.isAutoUpdate());
            currentCrl.setAutoUpdateCheckTimer(crl.getAutoUpdateCheckTimer());
            currentCrl.setNextUpdate(crl.getNextUpdate());
            currentCrl.setUpdateUrl(crl.getUpdateURL());
            if (crl.getX509CRL() != null) {
                currentCrl.setCrl(crl.getX509CRL().getCrlBytes());
            }
            persistenceManager.updateEntity(currentCrl);
        }
    }

    /**
     * @param crl
     * @param currentCrl
     */
    private void setCrlConfigParams(final ExternalCRLInfo crl, final CAEntityData caEntityRoot) {
        final ExternalCRLInfoData rootCrlInfo = caEntityRoot.getCertificateAuthorityData().getExternalCrlInfoData();
        if (rootCrlInfo != null) {
            // if rootCrlInfo is present we use the user config parameters instead of the defaul values
            crl.setAutoUpdateCheckTimer(rootCrlInfo.getAutoUpdateCheckTimer());
            crl.setAutoUpdate(rootCrlInfo.isAutoUpdate());
            setCrlNextUpdate(crl);
        } else {
            // Set default Value for CRL Info
            crl.setAutoUpdateCheckTimer(0);
            crl.setAutoUpdate(false);
            setCrlNextUpdate(crl);
            // get the crl information from one of associated and overwrite the default value if an associated exist
            final Set<CAEntityData> associated = caEntityRoot.getAssociated();
            for (final CAEntityData subExtCA : associated) {
                final ExternalCRLInfoData crlSubCA = subExtCA.getCertificateAuthorityData().getExternalCrlInfoData();
                if (crlSubCA != null) {
                    crl.setAutoUpdateCheckTimer(crlSubCA.getAutoUpdateCheckTimer());
                    crl.setAutoUpdate(crlSubCA.isAutoUpdate());
                    setCrlNextUpdate(crl);
                    return;
                }
            }
        }
    }

    /**
     * @param extCAName
     * @return
     */
    public List<ExternalCRLInfo> getExternalCRLInfoForExtCA(final String extCAName) throws ExternalCANotFoundException, ExternalCRLNotFoundException, ExternalCRLEncodedException, PersistenceException {

        final Query query = persistenceManager.getEntityManager().createQuery("select ec from CAEntityData ec  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true");
        query.setParameter("name", extCAName);

        final List<CAEntityData> caEntityDatas = query.getResultList();
        final List<ExternalCRLInfo> crls = new ArrayList<>();

        if (!caEntityDatas.isEmpty()) {
            if (caEntityDatas.get(0).getCertificateAuthorityData().getExternalCrlInfoData() != null) {
                crls.add(crlMapper.toAPIFromModel(caEntityDatas.get(0).getCertificateAuthorityData().getExternalCrlInfoData()));
            }
            for (final CAEntityData caEntityDataAssociated : caEntityDatas.get(0).getAssociated()) {
                if (caEntityDataAssociated.getCertificateAuthorityData().getExternalCrlInfoData() != null) {
                    crls.add(crlMapper.toAPIFromModel(caEntityDataAssociated.getCertificateAuthorityData().getExternalCrlInfoData()));
                }
            }
        } else {
            throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NOT_FOUND);
        }

        if (crls.size() == 0) {
            throw new ExternalCRLNotFoundException(ErrorMessages.EXTERNAL_CA_CRL_NOT_FOUND);
        }

        return crls;
    }

    /**
     * Return the list of TrustProfile which are using the ExtCA.
     *
     * @param extCAData
     *            the ExtCA data
     * @return the list of TrustProfile which are using the ExtCA.
     */
    public List<String> getTrustProfileNamesUsingExtCA(final CAEntityData extCAData) throws PersistenceException {
        final List<String> trustProfileNames = new ArrayList<String>();

        List<TrustProfileData> trustProfileDatas;

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("externalca_id", extCAData.getId());
        attributes.put("is_active", true);

        trustProfileDatas = persistenceManager.findEntitiesByAttributes(trustProfileQuery, attributes);

        for (int i = 0; i < trustProfileDatas.size(); i++) {
            if (trustProfileDatas.get(i).isActive()) {
                trustProfileNames.add(trustProfileDatas.get(i).getName());
            }
        }

        return trustProfileNames;
    }

    public List<ExternalCRLInfoData/* CAEntityData */> getExpiredCRLs(final Date validation) {
        // List<CAEntityData> caEntityDatas = new ArrayList<CAEntityData>();
        List<ExternalCRLInfoData> externalCrlInfoData = new ArrayList<ExternalCRLInfoData>();
        final Map<String, Object> attributes = new HashMap<String, Object>();

        final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        final String validityStr = sdf.format(validation);
        attributes.put("nextUpdateDate", validityStr);
        attributes.put("emptyString", "");
        try {
            logger.info("Query in queryForExternalCRLByFilter: {} " , queryForExternalCRLByFilter);
            externalCrlInfoData = persistenceManager.findEntitiesByAttributes(queryForExternalCRLByFilter, attributes);
        } catch (final PersistenceException persistenceException) {
            logger.debug("Unexpected Error in retrieving entities with Expired CRLs ", persistenceException);
            logger.error("Unexpected Error in retrieving entities with Expired CRLs. {}", persistenceException.getMessage());
        }

        return externalCrlInfoData;
    }

    /**
     * This method fetches latest {@link CertificateGenerationInfoData} of the given CA.
     *
     * @param caEntityName
     *            name of the CA.
     * @return {@link CertificateGenerationInfoData}
     *
     * @throws CertificateServiceException
     *             Thrown in case any database issue occurred.
     * @throws InvalidOperationException
     *             Thrown when CertificateGeneartionInfo is not found
     */
    public CertificateGenerationInfoData getLatestCertificateGenerationInfo(final String caEntityName) throws CertificateServiceException, InvalidOperationException {

        try {
            final Query query = persistenceManager.getEntityManager().createQuery(queryForFetchLatestCSR);
            query.setParameter("name", caEntityName);
            query.setFirstResult(0);

            final List<CertificateGenerationInfoData> certificateGenerationInfoData = query.getResultList();
            if (ValidationUtils.isNullOrEmpty(certificateGenerationInfoData)) {
                logger.error(ErrorMessages.CSR_NOT_FOUND, " for CA {} ", caEntityName);
                throw new InvalidOperationException(ErrorMessages.CSR_NOT_FOUND);
            }
            return certificateGenerationInfoData.get(0);

        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.CSR_NOT_FOUND, " for CA {} ", caEntityName, persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.CSR_NOT_FOUND, persistenceException);
        }

    }

    /**
     * This method is used to fetch latest CSR for the given CA from the database
     *
     * @param caName
     *            for which latest CSR has to be fetched.
     * @return csr in byte array
     *
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while fetching CSR.
     * @throws InvalidOperationException
     *             Thrown when the certificateGenerationInfo is not found.
     */
    public byte[] getCSR(final String caName) throws CertificateServiceException, InvalidOperationException {

        final CertificateGenerationInfoData certificateGenerationInfoData = getLatestCertificateGenerationInfo(caName);
        final CertificateRequestData certificateRequestData = certificateGenerationInfoData.getCertificateRequestData();

        final byte[] csr = certificateRequestData.getCsr();
        return csr;
    }

    public void setExpiredCRLs(final ExternalCRLInfoData externalCrlInfoData) throws PersistenceException {
        persistenceManager.updateEntity(externalCrlInfoData);
    }

    /**
     * TODO BULLS
     *
     * @param issuerCAEntityData
     */
    public void updateExtCA(final CAEntityData issuerCAEntityData) throws PersistenceException {
        persistenceManager.updateEntity(issuerCAEntityData);
    }

    /**
     * TODO BULLS
     *
     * @param associated
     */
    public void deleteExtCA(final CAEntityData associated) throws PersistenceException {
        persistenceManager.deleteEntity(associated);
    }

    /**
     * TODO BULLS
     *
     * @param crl
     */
    public void deleteExternalCRLInfo(final ExternalCRLInfoData crl) throws PersistenceException {
        persistenceManager.deleteEntity(crl);
    }

    /**
     * Update isIssuerExternalCA as false. Use to Roll back the certificate of internal root CA which is signed by external root CA to PKI self signed certificate.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @throws CertificateServiceException
     *             Thrown in case any database issue occurs.
     */
    public void updateIsIssuerExternalCAFlag(final CAEntityData caEntityData, final boolean isIssuerExternalCA) throws CertificateServiceException {
        try {
            caEntityData.getCertificateAuthorityData().setIssuerExternalCA(isIssuerExternalCA);
            persistenceManager.updateEntity(caEntityData);
        } catch (final PersistenceException persistenceException) {
            logger.error(INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(INTERNAL_ERROR, persistenceException);
        }
    }

    /**
     * Updates isIssuerExternalCA field in caEntity table for given internal root CA name. This is used to Roll back the certificate of internal root CA which is signed by external root CA to PKI self
     * signed certificate.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @throws CANotFoundException
     *             is thrown if CA is not found in the database.
     * @throws CertificateServiceException
     *             Thrown in case any database issue occurs.
     */

    public void checkAndUpdateIsIssuerExternalCA(final String caEntityName) throws CANotFoundException, CertificateServiceException {

        try {
            final CAEntityData caEntityData = getCAEntity(caEntityName);
            final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();

            if (certificateAuthorityData.isRootCA() && certificateAuthorityData.isIssuerExternalCA()) {
                updateIsIssuerExternalCA(caEntityData, false);
            }
        } catch (final EntityServiceException entityServiceException) {
            logger.error(INTERNAL_ERROR, entityServiceException.getMessage());
            throw new CertificateServiceException(INTERNAL_ERROR, entityServiceException);
        }
    }

    private void updateIsIssuerExternalCA(final CAEntityData caEntityData, final boolean isIssuerExternalCA) throws CertificateServiceException {
        try {
            caEntityData.getCertificateAuthorityData().setIssuerExternalCA(isIssuerExternalCA);
            persistenceManager.updateEntity(caEntityData);
        } catch (final PersistenceException persistenceException) {
            logger.error(INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(INTERNAL_ERROR, persistenceException);
        }
    }

    /**
     * Sets IssuerCertificate and IssuerCA fields to certificate.
     *
     * @param x509Certificate
     *            x509Certificate to which issuer Certificate will be set.
     * @param issuerCaEntityData
     *            issuerCAEntityData is the issuer id which will be set.
     * @param issuerCertificateData
     *            issuerCertificateData is the issuer certificate which will be set.
     * @throws CertificateServiceException
     *             Thrown in the event of not able to set IssuerCertificate to external CA certificate.
     */
    public void updateIssuerCAandCertificate(final CertificateData certificateData, final CAEntityData issuerCaEntityData, final CertificateData issuerCertificateData)
            throws CertificateServiceException {

        try {
            certificateData.setIssuerCertificate(issuerCertificateData);
            certificateData.setIssuerCA(issuerCaEntityData);
            persistenceManager.updateEntity(certificateData);

        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        }
    }

    /**
     * This method is used to get certificates count based on given entityName and serialNumber.
     *
     * @param entityName
     *            for which certificate has to be fetched
     * @param serialNumber
     *            certificate's serial number
     * @return certificates count.
     */
    public int getCertificatesCount(final String entityName, final String serialNumber) throws PersistenceException {
        final Query query = persistenceManager
                .getEntityManager()
                .createQuery(
                        "select c from CertificateData c where c.id in(select p.id from CAEntityData ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and p.serialNumber= :serialnumber)");
        query.setParameter("name", entityName);
        query.setParameter("serialnumber", serialNumber);

        final List<CertificateData> certificateDatas = query.getResultList();
        return certificateDatas.size();

    }

    /**
     * This method will return the list of CA certificates which are expired and has to be unpublished.
     * 
     * @return Map of CA name and its list of certificates.
     * @throws CertificateServiceException
     *             Thrown in case any database issue occurs.
     */
    public Map<String, List<Certificate>> getExpiredCACertificatesToUnpublish() throws CertificateServiceException {
        final Map<String, List<Certificate>> caCertsMap = new HashMap<String, List<Certificate>>();
        try {
            final List<String> caNames = getAllCANameByStatus(CAStatus.ACTIVE, CAStatus.INACTIVE);
            for (final String caName : caNames) {
                final List<CertificateData> certificateDatas = getCertificateDatas(caName, CertificateStatus.EXPIRED);
                if (certificateDatas != null) {
                    final List<CertificateData> certsToBeAdded = new ArrayList<CertificateData>();
                    for (final CertificateData certificateData : certificateDatas) {
                        if (certificateData.isPublishedToTDPS()) {
                            certsToBeAdded.add(certificateData);
                        }
                    }
                    if (!certsToBeAdded.isEmpty()) {
                        caCertsMap.put(caName, certificateModelMapper.toObjectModel(certsToBeAdded));
                    }
                }
            }
        } catch (final CertificateException | PersistenceException | IOException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, exception);
        }
        return caCertsMap;
    }

    /**
     * This method will return the list of CA names of the CA entities with the given CA statuses.
     * 
     * @param caStatuses
     *            Status of the CAs by which the CA names are to be fetched.
     * @return List of CA names.
     * @throws PersistenceException
     *             Thrown in case any database issue occurs.
     */
    @SuppressWarnings("unchecked")
    public List<String> getAllCANameByStatus(final CAStatus... caStatuses) throws PersistenceException {
        final List<Integer> caStatusIds = new ArrayList<>();
        for(CAStatus caStatus : caStatuses) {
             caStatusIds.add(caStatus.getId());
        }
        final Query query = persistenceManager.getEntityManager().createQuery(CA_NAMES_BY_STATUS);
        query.setParameter("status", caStatusIds);
        return query.getResultList();
    }

    /**
     * This method gets all the certificates which are issued by given CA Id.
     *
     * @param issuerCAId
     *            All certificates issued by issuer CA Id will fetched.
     * @return list of certificates which got issued by issuer CA Id.
     * @throws PersistenceException
     *             Thrown in case any database issue occurs.
     */
    public List<CertificateData> getCertificateDatas(final long issuerCAId) throws PersistenceException {

        final Query query = persistenceManager.getEntityManager().createQuery(SUBCA_CERTIFICATES_BY_ISSUER);
        query.setParameter("issuerCAId", issuerCAId);

        final List<CertificateData> certificateDatas = query.getResultList();

        if (ValidationUtils.isNullOrEmpty(certificateDatas)) {
            return null;
        }
        return certificateDatas;
    }
    
    private String fromSubjectAltName(final SubjectAltName subjectAltName) {
        if (subjectAltName != null) {
            return JsonUtil.getJsonFromObject(subjectAltName);
        }

        return null;
    }
}