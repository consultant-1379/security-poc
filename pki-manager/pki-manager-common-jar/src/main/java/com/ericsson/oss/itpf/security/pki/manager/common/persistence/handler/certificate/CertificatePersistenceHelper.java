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

//import static com.ericsson.oss.itpf.security.pki.manager.common.utils.CommonErrorMessages.CERTIFICATE_NOT_FOUND;
import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.UNEXPECTED_ERROR;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.CertificateStatusUpdateFailedException;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.certificate.CertificateModelMapperV1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.result.mapper.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.FilterResponseType;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CertificateInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * Helper class to get Certificate and CertificateData object.
 * 
 */
public class CertificatePersistenceHelper {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificateModelMapper certificateModelMapper;

    @Inject
    CertificateModelMapperV1 certificateModelMapperV1;

    @Inject
    CertificateFilterDynamicQueryBuilder certificateDynamicQueryBuilder;

    private static final String updateCertStatusToExpiredQuery = "UPDATE  CertificateData c SET  c.status=(:status) WHERE c.notAfter <= (:currDate) AND c.status IN (:certStatus)";
    private static final String CAENTITY_CERTIFICATES_BY_CANAME_AND_SERIAL_NUMBER_QUERY = "select c from CertificateData c where c.id in(select cd.id from CAEntityData caData inner join caData.certificateAuthorityData.certificateDatas cd  WHERE caData.certificateAuthorityData.name = :name and cd.serialNumber = :serialNumber)";

    private static final String CA_CERT_EXP_NOTIFICATION_DETAILS_QUERY = "SELECT ca.name,c.subject_dn,c.serial_number,date(c.not_after)-CURRENT_DATE,cend.period_before_expiry,cend.notification_severity,cend.frequency_of_notification,cend.notification_message FROM caentity ca JOIN ca_certificate cac ON ca.id= cac.ca_id JOIN certificate c ON c.id= cac.certificate_id JOIN ca_cert_exp_notification_details cacend ON  ca.id= cacend.ca_id  JOIN certificate_expiry_notification_details cend ON cacend.ca_cert_exp_not_details_id = cend.id  JOIN notification_severity ns ON cend.notification_severity= ns.id  where date(c.not_after)-CURRENT_DATE <= cend.period_before_expiry and  date(c.not_after)-CURRENT_DATE >= 0  and c.status_id in (1,4) ORDER BY cend.period_before_expiry ASC";
    private static final String ENTITY_CERT_EXP_NOTIFICATION_DETAILS_QUERY = "SELECT ent.name,c.subject_dn,c.serial_number,date(c.not_after)-CURRENT_DATE,cend.period_before_expiry,cend.notification_severity,cend.frequency_of_notification,cend.notification_message FROM entity ent JOIN entity_certificate cac ON ent.id= cac.entity_id JOIN certificate c ON c.id= cac.certificate_id JOIN entity_cert_exp_notification_details entcend ON  ent.id= entcend.entity_id  JOIN certificate_expiry_notification_details cend ON entcend.entity_cert_exp_not_details_id = cend.id  JOIN notification_severity ns ON cend.notification_severity= ns.id  where date(c.not_after)-CURRENT_DATE <= cend.period_before_expiry and  date(c.not_after)-CURRENT_DATE > 0  and c.status_id in (1,4) ORDER BY cend.period_before_expiry ASC";
    private static final String GET_CERTIFICATES_ISSUED_BY_EXTERNAL_CA = "select cerd from CertificateData cerd,CAEntityData ced where cerd.issuerCA=ced.id and ced.externalCA=true and cerd.status in(1,4)";
    private static final String UPDATE_CERT_STATUS_TO_REVOKE_QUERY = "update certificate Set status_id=3 where serial_number= :serialNumber";

    /**
     * This method will fetch certificate for the given serial number and issuer name
     * 
     * @param certificateIdentifier
     *            is the object of CertificateIdentifier, has the fields issuerName and serialNumber.
     * @return Certificate - Returns the Certificate for the given entity
     * 
     * @throws CertificateServiceException
     *             thrown when there are any DB Errors while persisting.
     * @throws CertificateNotFoundException
     *             thrown when no valid Certificate found for Entity.
     */
    public Certificate getCertificate(final CertificateIdentifier certificateIdentifier) throws CertificateServiceException, CertificateNotFoundException, IssuerNotFoundException {
        logger.info("Enter into getCertificate method to fetch certificate");

        CAEntityData caEntityData;

        try {
            caEntityData = persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH);
        } catch (final PersistenceException pe) {
            logger.error("Error occured while fetching issuer");
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, pe);
        }
        if (caEntityData == null) {
            logger.error("Issuer not found in CA data");
            throw new IssuerNotFoundException(ErrorMessages.ISSUER_NOT_FOUND);
        }
        List<Certificate> certDataList;
        Certificate certificate = null;
        certDataList = getCertificateBySerialNumber(certificateIdentifier.getSerialNumber());
        for (final Certificate cert : certDataList) {
            if (cert.getIssuer().getId() == caEntityData.getId()) {
                certificate = cert;
            }
        }
        if (certificate == null) {
            logger.error(" Certificate not found with the given serial number {} and issuer name {}", certificateIdentifier.getSerialNumber(), certificateIdentifier.getIssuerName());
            throw new CertificateNotFoundException(ErrorMessages.ACTIVE_CERTIFICATE_NOT_FOUND);
        }
        return certificate;

    }

    /**
     * This method will fetch certificate for the given serial number
     *
     * @param serialNumber
     *            - is the certificate serialNumber.
     * @return - List of certificates
     * @throws CertificateServiceException
     *             - thrown when there are any DB Errors while persisting.
     * @throws CertificateNotFoundException
     *             - thrown when no valid Certificate found for Entity.
     */
    public List<Certificate> getCertificateBySerialNumber(final String serialNumber) throws CertificateServiceException, CertificateNotFoundException {
        logger.info("Enter into getCertificate method to fetch certificate");
        final List<Certificate> certificateList;
        final Map<String, Object> certificateMap = new HashMap<String, Object>();
        certificateMap.put("serialNumber", serialNumber);
        List<CertificateData> certDataList;
        try {
            certDataList = persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap);
        } catch (final PersistenceException pe) {
            logger.error("Error when fetching certificate");
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, pe);
        }
        if (ValidationUtils.isNullOrEmpty(certDataList)) {
            logger.error(" Certificate not found with the given serial num {}", serialNumber);
            throw new CertificateNotFoundException(ErrorMessages.ACTIVE_CERTIFICATE_NOT_FOUND);
        } else {
            try {
                certificateList = certificateModelMapper.toObjectModel(certDataList);
            } catch (final IOException ioException) {
                logger.error(UNEXPECTED_ERROR, ioException.getMessage());
                throw new CertificateServiceException(UNEXPECTED_ERROR + ioException);
            } catch (final java.security.cert.CertificateException certificateException) {
                logger.error(UNEXPECTED_ERROR, certificateException.getMessage());
                throw new CertificateServiceException(UNEXPECTED_ERROR + certificateException);
            }
            return certificateList;
        }
    }

    /**
     * This method will get the CertificateData JPA object from database when a Certificate object is passed
     * 
     * @param certificate
     *            is the Certificate Class contain the certificate details
     * 
     * @return CertificateData is the CertificateData Class contain the certificate details
     * 
     * @throws CertificateServiceException
     *             when there is any internal error like any internal database failures during the revocation.
     * 
     */
    public CertificateData getCertificateData(final Certificate certificate) throws CertificateServiceException {
        List<CertificateData> certificateList;
        final Map<String, Object> mapCertificate = new HashMap<String, Object>();
        mapCertificate.put("id", certificate.getId());
        try {
            certificateList = persistenceManager.findEntitiesWhere(CertificateData.class, mapCertificate);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error occured while fetching certificate" + persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        }
        return certificateList.get(0);
    }

    /**
     * This method will update certificate status to EXPIRED for all certificates whose validity has expired.
     * 
     * @throws CertificateException
     */
    public void updateCertificateStatusToExpired() throws CertificateStatusUpdateFailedException {
        logger.info("Updating the certificate status in pki-manager");
        int updatedEntityCount = 0;
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        final List<Integer> certStatus = new ArrayList<Integer>();
        certStatus.add(CertificateStatus.ACTIVE.getId());
        certStatus.add(CertificateStatus.INACTIVE.getId());
        certStatus.add(CertificateStatus.REVOKED.getId());
        parameters.put("status", certStatus);
        final Query query = persistenceManager.getEntityManager().createQuery(updateCertStatusToExpiredQuery);
        query.setParameter("status", CertificateStatus.EXPIRED.getId());
        query.setParameter("currDate", new Date());
        query.setParameter("certStatus", certStatus);
        try {
            updatedEntityCount = query.executeUpdate();
        } catch (final PersistenceException | IllegalStateException e) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating Certificate status to expired.");
            throw new CertificateStatusUpdateFailedException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating Certificate status to expired", e);
        }
        logger.info("Updated certificate status for {} entities in pki-manager", updatedEntityCount);
    }

    /**
     * get the certificate chain from entity Certificate to RootCA Certificate.
     * 
     * @param certificate
     *            Entity Certificate or CAEntity Certificate.
     * @param isInactiveValid
     *            boolean value which specifies whether an Inactive certificate is valid for the chain building or not.
     * @return certificates Certificate chain as a list of certificates.
     * 
     * @return null if any of the certificates in the chain is revoked or expired.
     * 
     * @throws CertificateServiceException
     *             Thrown in the event of not able to build the certificate from byte array (or) Thrown in the event of corrupted data, or an incorrect structure of certificate.
     */
    public List<Certificate> getCertificateChain(final Certificate certificate,final boolean isInactiveValid) throws CertificateServiceException {

        List<Certificate> certificates = null;

        final List<CertificateData> certificateDatas = new ArrayList<CertificateData>();
        final CertificateData certificateData = getCertificateData(certificate);
        certificateDatas.add(certificateData);

        CertificateData issuerCertificateData = certificateData.getIssuerCertificate();

        while (issuerCertificateData != null) {

            switch (CertificateStatus.getStatus(issuerCertificateData.getStatus())) {
            case REVOKED:
            case EXPIRED:
                logger.warn("Invalid Certificate chain. issuer CA - {} certificate is either expired or revoked", certificate.getIssuer());
                return null;
            case INACTIVE:
                if (!isInactiveValid) {
                    logger.warn("Invalid Certificate chain. issuer CA - {} certificate is in inactive state", certificate.getIssuer());
                    return null;
                }
            default:
            }
            certificateDatas.add(issuerCertificateData);
            issuerCertificateData = issuerCertificateData.getIssuerCertificate();
        }

        try {
            certificates = certificateModelMapperV1.toApi(certificateDatas, MappingDepth.LEVEL_1);
        } catch (final java.security.cert.CertificateException | IOException excpetion) {
            throw new CertificateServiceException(UNEXPECTED_ERROR + excpetion);
        }

        return certificates;
    }

    /**
     * This method will generate dynamic query with matching filter to be applied for list/count of certificates.
     * 
     * @param certificateFilter
     *            The filter data to be applied to get certificates.
     * @param entityTypeFilter
     *            The entityTypeFilter is specifies CA_ENTITY/ENTITY/BOTH.
     * @return list/count certificates.
     * @throws CertificateException
     */
    public Object getCertificates(final CertificateFilter certificateFilter, final EnumSet<EntityType> entityTypeFilter, final FilterResponseType responseType) throws CertificateException,
            PersistenceException {

        logger.debug(" Certificate Filter Input for Genarating Dynamic Query {}", certificateFilter);

        final Map<String, Object> parameters = new HashMap<String, Object>();

        final StringBuilder dynamicQuery = certificateDynamicQueryBuilder.buildCertificatesQuery(certificateFilter, entityTypeFilter, responseType, parameters);

        final StringBuilder query = certificateDynamicQueryBuilder.replaceQueryString(entityTypeFilter, dynamicQuery, responseType);

        logger.debug("Certifcate Filter Dynamic Query : {}", query);

        final Object result = getFilteredCertificatesResult(query, parameters, certificateFilter.getLimit(), certificateFilter.getOffset(), responseType);

        return result;
    }

    private Object getFilteredCertificatesResult(final StringBuilder dynamicQuery, final Map<String, Object> parameters, final Integer limit, final Integer offset,
            final FilterResponseType certFilterResponseType) {

        Object result = null;
        if (certFilterResponseType == FilterResponseType.LIST) {
            result = persistenceManager.findEntitiesByNativeQuery(CertificateData.class, dynamicQuery.toString(), parameters, offset, limit);
        } else if (certFilterResponseType == FilterResponseType.COUNT) {
            result = persistenceManager.findEntityCountByNativeQuery(dynamicQuery.toString(), parameters);
        }
        return result;
    }

    /**
     * Returns list of entities corresponding certificates issued for a given issuerCertificateIds and entity certificate status.
     * 
     * @param issuerCertificateIds
     *            issuer CertificateIds for caEntityName
     * @param status
     *            The list of {@link CertificateStatus} values for which Entity Certificates have to be listed
     * 
     * @return list of entities corresponding certificates for the given issuerCertificateIds and status.
     * 
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public List<CertificateInfo> getCertificatesInfoByIssuerCA(final Long[] issuerCertificateIds, final CertificateStatus... status) throws PersistenceException {

        logger.debug("Fetching list of certificates Issued By CA CertificateIds {}, status {} ", issuerCertificateIds, status);

        // TODO :: TORF-96665 - Refactor postgres constructs in the native
        // quiries
        final StringBuilder certsIssuedByCA = new StringBuilder();

        certsIssuedByCA
                .append("SELECT c.id,CASE WHEN ca.name is null THEN e.name ELSE ca.name END,CASE WHEN ca.name is null THEN false ELSE true END,c.subject_dn,c.subject_alt_name,c.serial_number,c.not_after,c.not_before,c.status_id from certificate c");
        certsIssuedByCA.append(" LEFT JOIN ca_certificate cc on c.id = cc.certificate_id  LEFT JOIN caentity ca on ca.id = cc.ca_id  ");
        certsIssuedByCA.append(" LEFT JOIN entity_certificate ec on c.id = ec.certificate_id LEFT JOIN entity e on e.id = ec.entity_id ");
        certsIssuedByCA.append(" WHERE c.issuer_certificate_id IN " + certificateDynamicQueryBuilder.inOperatorValues(issuerCertificateIds));
        certsIssuedByCA.append(" and c.status_id IN " + certificateDynamicQueryBuilder.inOperatorValues(certificateDynamicQueryBuilder.getCertificateStatusArray(status)));
        certsIssuedByCA.append(certificateDynamicQueryBuilder.orderBy("c.issued_time", "DESC"));

        logger.info("Query for List certifcates Issued By CA {}", certsIssuedByCA);

        final Query query = persistenceManager.getEntityManager().createNativeQuery(certsIssuedByCA.toString());

        final List<Object[]> resultSet = (List<Object[]>) query.getResultList();

        final List<CertificateInfo> certificateInfos = new ArrayList<CertificateInfo>();

        if (resultSet.isEmpty()) {
            return certificateInfos;
        }

        for (final Object[] result : resultSet) {
            final CertificateInfo certificateInfo = new CertificateInfo();
            certificateInfo.setId(((BigInteger) result[0]).longValue());
            certificateInfo.setEntityName((String) result[1]);
            certificateInfo.setCAEntity((Boolean) result[2]);
            if (result[3] != null) {
                final String subject = (String) result[3];
                certificateInfo.setSubject(new Subject().fromASN1String(subject));
            }
            if (result[4] != null) {
                final String subjectAltName = (String) result[4];
                certificateInfo.setSubjectAltName(JsonUtil.getObjectFromJson(SubjectAltName.class, subjectAltName));
            }
            certificateInfo.setSerialNumber((String) result[5]);
            certificateInfo.setNotAfter((Date) result[6]);
            certificateInfo.setNotBefore((Date) result[7]);
            certificateInfo.setStatus(CertificateStatus.getStatus((Integer) result[8]));

            certificateInfos.add(certificateInfo);
        }
        return certificateInfos;
    }

    /**
     * Get the certificate Id's for a given {@link DNBasedCertificateIdentifier}
     *
     * @param dnBasedCertificateIdentifier
     *            contains SubjectDn,issuerDN and Serail Number
     * @return certificate Id's array
     *
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public Long[] getCertificates(final DNBasedCertificateIdentifier dnBasedCertificateIdentifier) throws PersistenceException {

        logger.debug(" Certificate Filter Input for Genarating Dynamic Query {}", dnBasedCertificateIdentifier);

        final StringBuilder dynamicQuery = new StringBuilder();

        dynamicQuery.append("SELECT id from  CertificateData cert ");
        if (dnBasedCertificateIdentifier.getIssuerDN() != null) {
            dynamicQuery.append(" INNER JOIN cert.issuerCertificate ");
        }
        final Map<String, Object> parameters = certificateDynamicQueryBuilder.where(dnBasedCertificateIdentifier, dynamicQuery);

        final List<Object> resultList = persistenceManager.findEntitiesByAttributes(dynamicQuery.toString(), parameters);

        Long[] certificateIds = new Long[resultList.size()];

        if (resultList.isEmpty()) {
            return certificateIds;
        }
        int i = 0;
        for (final Object result : resultList) {
            final long certificateId = ((Long) result);
            certificateIds[i++] = certificateId;
        }

        logger.debug("Certifcate Filter Dynamic Query : {}", dynamicQuery);

        return certificateIds;
    }

    /**
     * This method validates the certificate chain to check if there are any Revoked or Expired certs in chain.
     *
     * @param Certificate
     *            {@link Certificate} Object
     * @param invalidCertStatusSet
     *            enum set containing set of Certificate statuses which are invalid like revoked or expired.
     *
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    public void validateCertificateChain(final Certificate certificate, final EnumSet<CertificateStatus> invalidCertStatusSet) throws ExpiredCertificateException, RevokedCertificateException {

        validateCertificateChain(getCertificateData(certificate), invalidCertStatusSet);

    }

    /**
     * This method validates the certificate chain to check if there are any Revoked or Expired certs in chain.
     * 
     * @param CertificateData
     *            {@link CertificateData} Object
     * @param invalidCertStatusSet
     *            enum set containing set of Certificate statuses which are invalid like revoked or expired.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    public void validateCertificateChain(final CertificateData certificateData, final EnumSet<CertificateStatus> invalidCertStatusSet) throws ExpiredCertificateException, RevokedCertificateException {

        if (certificateData.getStatus().intValue() == CertificateStatus.REVOKED.getId() && invalidCertStatusSet.contains(CertificateStatus.REVOKED)) {
            logger.error(ErrorMessages.ISSUER_CERTIFICATE_ALREADY_REVOKED);
            throw new RevokedCertificateException(ErrorMessages.ISSUER_CERTIFICATE_ALREADY_REVOKED + "Certificate serial number:  " + certificateData.getSerialNumber() + " and Certificate subject:  "
                    + certificateData.getSubjectDN());
        } else if (certificateData.getStatus().intValue() == CertificateStatus.EXPIRED.getId() && invalidCertStatusSet.contains(CertificateStatus.EXPIRED)) {
            logger.error(ErrorMessages.ISSUER_CERTIFICATE_ALREADY_EXPIRED);
            throw new ExpiredCertificateException(ErrorMessages.ISSUER_CERTIFICATE_ALREADY_EXPIRED + "Certificate serial number:  " + certificateData.getSerialNumber() + " and Certificate subject:  "
                    + certificateData.getSubjectDN());
        }

        if (certificateData.getIssuerCertificate() != null) {
            validateCertificateChain(certificateData.getIssuerCertificate(), invalidCertStatusSet);
        }
    }

    /**
     * This method validates the certificate chain to check if there are any Revoked or Expired certs in chain.
     * 
     * @param caCertIdentifier
     *            holder object containing CA name and its certificate serial number.
     * @param invalidCertStatusSet
     *            enum set containing set of Certificate statuses which are invalid like revoked or expired.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws CertificateNotFoundException
     *             is throw when the certificate is not found.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    public void validateCertificateChain(final CACertificateIdentifier caCertIdentifier, final EnumSet<CertificateStatus> invalidCertStatusSet) throws ExpiredCertificateException,
            CertificateNotFoundException, RevokedCertificateException {
        CertificateData certificateData = null;
        try {
            certificateData = getCertificate(caCertIdentifier);
        } catch (final NoResultException e) {
            final String caName = caCertIdentifier.getCaName();
            final String certSerialNumber = caCertIdentifier.getCerficateSerialNumber();
            logger.error("Certificate not found for the CA {} with the serial number {}", caName, certSerialNumber);
            throw new CertificateNotFoundException("Certificate not found for the CA " + caName + " with the serial number " + certSerialNumber, e);
        }
        validateCertificateChain(certificateData, invalidCertStatusSet);
    }

    /**
     * This method returns Object Model Certificate {@link Certificate} from the given X509Certificate
     * 
     * @param x509Certificate
     *            object of X509Certificate
     * @return Certificate returns the Certificate for the given x509Certificate
     * @throws CertificateServiceException
     *             thrown when there are any DB Errors while persisting.
     * @throws CertificateNotFoundException
     *             thrown when no valid Certificate found for Entity.
     */
    public Certificate getCertificate(final X509Certificate x509Certificate) throws CertificateServiceException, CertificateNotFoundException {

        final String serialNumber = Long.toHexString(x509Certificate.getSerialNumber().longValue());
        logger.info("serialNumber received as: {}", serialNumber);

        final List<Certificate> certificateList = getCertificateBySerialNumber(serialNumber);
        logger.debug("No of Certificates retrived from PKI System is: {}", certificateList.size());

        for (final Certificate certificate : certificateList) {

            final String inputCertIssuerDN = x509Certificate.getIssuerX500Principal().toString();
            logger.debug("Certificate issuerDN in request is {}", inputCertIssuerDN);

            final String certIssuerDN = certificate.getX509Certificate().getIssuerX500Principal().toString();
            logger.debug("Certificate issuerDN in PKI system is {}", certIssuerDN);

            final boolean isMatched = SubjectUtils.isDNMatched(inputCertIssuerDN, certIssuerDN);
            if (isMatched) {
                logger.debug("Valid Certificate Found with Id: {}", certificate.getId());
                return certificate;
            }

        }
        throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND + " with the serial number " + serialNumber);

    }

    /**
     * This method gets CA certificate for which CRL needs to be generated.
     * 
     * @param caCertificateIdentifier
     *            object which contains ca name and serial number for which CRL need to be generated.
     * @return CertificateData object
     */
    public CertificateData getCertificate(final CACertificateIdentifier caCertificateIdentifier) throws NoResultException {

        final Query query = persistenceManager.getEntityManager().createQuery(CAENTITY_CERTIFICATES_BY_CANAME_AND_SERIAL_NUMBER_QUERY);
        query.setParameter("name", caCertificateIdentifier.getCaName());
        query.setParameter("serialNumber", caCertificateIdentifier.getCerficateSerialNumber());

        final CertificateData certificateData = (CertificateData) query.getSingleResult();

        return certificateData;
    }

    /**
     * This method gets the CA or Entity certificate expire notification details.
     * 
     * @param entityType
     *            type of entity.
     * @return List of CertificateExpiryNotificationDetailsDTO object
     */
    public List<CertificateExpiryNotificationDetails> getCertExpiryNotificationDetails(final EntityType entityType) throws PersistenceException {

        final List<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails = new ArrayList<CertificateExpiryNotificationDetails>();
        Query query = null;
        if (entityType == EntityType.CA_ENTITY) {
            query = persistenceManager.getEntityManager().createNativeQuery(CA_CERT_EXP_NOTIFICATION_DETAILS_QUERY);
        } else if (entityType == EntityType.ENTITY) {
            query = persistenceManager.getEntityManager().createNativeQuery(ENTITY_CERT_EXP_NOTIFICATION_DETAILS_QUERY);
        } else {
            throw new PersistenceException("Unsupported Entity Type.");
        }
        final List<Object[]> certificateExpiryNotificationDetailsList = (List<Object[]>) query.getResultList();
        if (ValidationUtils.isNullOrEmpty(certificateExpiryNotificationDetailsList)) {
            return certificateExpiryNotificationDetails;
        }
        for (final Object[] result : certificateExpiryNotificationDetailsList) {
            final CertificateExpiryNotificationDetails certExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
            certExpiryNotificationDetails.setName(((String) result[0]));
            certExpiryNotificationDetails.setSubjectDN((String) result[1]);
            certExpiryNotificationDetails.setSerialNumber((String) result[2]);
            certExpiryNotificationDetails.setNumberOfDays((Integer) result[3]);
            certExpiryNotificationDetails.setPeriodBeforeExpiry((Integer) result[4]);
            certExpiryNotificationDetails.setNotificationSeverity((Integer) result[5]);
            certExpiryNotificationDetails.setFrequencyOfNotification((Integer) result[6]);
            certExpiryNotificationDetails.setNotificationMessage((String) result[7]);
            certificateExpiryNotificationDetails.add(certExpiryNotificationDetails);
        }
        return certificateExpiryNotificationDetails;
    }

    /**
     * This method updates the Certificate Status to Revoke which are ACTIVE/INACTIVE
     * 
     * @param serialNumber
     *            of the certificate which should be updated to Revoked
     * @throws CertificateServiceException
     *             to indicate any internal database errors or any unconditional exceptions.
     */
    public void updateCertificateStatusToRevoke(final String serialNumber) throws CertificateServiceException {
        int updatedEntityCount = 0;
        final Query query = persistenceManager.getEntityManager().createNativeQuery(UPDATE_CERT_STATUS_TO_REVOKE_QUERY);
        query.setParameter("serialNumber", serialNumber);
        try {
            updatedEntityCount = query.executeUpdate();

        } catch (final PersistenceException | IllegalStateException e) {
            logger.error("Error while updating Certificate status");
            throw new CertificateServiceException("Error while updating Certificate status", e);
        }
        logger.debug("Updated Entity status for {} entities in pki-manager", updatedEntityCount);

    }

    /**
     * This method will return the ACTIVE/INACTIVE certificates which are issued by ExternalCA.
     * 
     * @return List of Certificates Issued by ExternalCA.
     */
    public List<CertificateData> getCertificatesIssuedByExternalCA() {
        final Query query = persistenceManager.getEntityManager().createQuery(GET_CERTIFICATES_ISSUED_BY_EXTERNAL_CA);
        final List<CertificateData> certificates = query.getResultList();
        return certificates;
    }
}
