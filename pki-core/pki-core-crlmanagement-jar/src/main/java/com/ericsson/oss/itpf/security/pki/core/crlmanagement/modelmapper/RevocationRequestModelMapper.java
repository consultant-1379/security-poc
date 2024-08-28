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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.modelmapper;

import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension.CrlEntryExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.util.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

/**
 * Class to perform mapping between Object model and JPA model for Revocation
 *
 * @author xbensar
 *
 */
public class RevocationRequestModelMapper {

    @Inject
    Logger logger;

    @Inject
    CertificateAuthorityModelMapper caEntityMapper;

    @Inject
    EntityModelMapper entityMapper;

    @Inject
    CertificateModelMapper certificateMapper;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * Convert RevocationRequestData object to RevocationRequest object model.
     *
     * @param revocationRequestData
     *            RevocationRequestData entity objects.
     * @return RevocationRequest api model objects.
     * @throws CRLGenerationException
     * @throws InvalidCRLGenerationInfoException
     *             thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     *
     * @throws RevocationServiceException
     *             Thrown in the event of any internal error occurs while mapping the data.
     *
     */
    public RevocationRequest toAPIModel(final RevocationRequestData revocationRequestData) throws CRLGenerationException, InvalidCRLGenerationInfoException, RevocationServiceException {
        try {
            final RevocationRequest revocationRequest = new RevocationRequest();
            if (revocationRequestData.getCaEntity() != null) {
                revocationRequest.setCaEntity(caEntityMapper.toAPIModel(revocationRequestData.getCaEntity()));
            }

            final List<Certificate> certificateList = new ArrayList<>();
            for (final CertificateData certificateData : revocationRequestData.getCertificatesToRevoke()) {

                certificateList.add(certificateMapper.mapToCertificate(certificateData));

            }
            revocationRequest.setCertificatesToBeRevoked(certificateList);
            if (revocationRequestData.getEntity() != null) {
                revocationRequest.setEntity(entityMapper.toAPIFromModel(revocationRequestData.getEntity()));
            }
            revocationRequest.setCrlEntryExtensions(JsonUtil.getObjectFromJson(CrlEntryExtensions.class, revocationRequestData.getCrlEntryExtensionsJSONData()));
            return revocationRequest;
        } catch (CertificateException | InvalidCertificateException e) {
            logger.debug("Error occured in the process of revocation while mapping model object to API object due to CertificateException. ", e);
            systemRecorder.recordError("PKI_CORE.REVOCATION_REQUEST_MODEL_MAPPER", ErrorSeverity.ERROR, "RevocationRequestModelMapper", "Revocation of certificate",
                    "Error occured in the process of revocation while mapping model object to API object due to CertificateException.");
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR);
        }
    }

    /**
     * Convert RevocationRequest object to RevocationRequestData object model.
     *
     * @param revocationRequest
     *            RevocationRequest entity objects.
     * @return RevocationRequestData jpa objects.
     * @throws CoreEntityNotFoundException
     *             thrown when given Entity doesn't exists.
     *
     * @throws RevocationServiceException
     *             Thrown in the event of any internal error occurs while mapping the data.
     *
     */
    public RevocationRequestData fromAPIModel(final RevocationRequest revocationRequest) throws RevocationServiceException {
        final RevocationRequestData revocationRequestData = new RevocationRequestData();
        final Set<CertificateData> certificateDataset = new HashSet<>();
        if (revocationRequest.getCaEntity() != null) {
            CertificateAuthorityData certificateAuthorityData = null;
            try {
                certificateAuthorityData = persistenceManager.findEntityByName(CertificateAuthorityData.class, revocationRequest.getCaEntity().getName(), Constants.NAME_PATH);
            } catch (final PersistenceException exception) {
                logger.error(ErrorMessages.ENTITY_NOT_FOUND, exception);
                throw new RevocationServiceException(ErrorMessages.ENTITY_NOT_FOUND + exception.getMessage());
            }
            revocationRequestData.setCaEntity(certificateAuthorityData);
        } else {
            EntityInfoData entityData = null;
            try {
                entityData = persistenceManager.findEntityByName(EntityInfoData.class, revocationRequest.getEntity().getName(), Constants.NAME_PATH);
            } catch (final PersistenceException exception) {
                logger.error(ErrorMessages.ENTITY_NOT_FOUND, exception);
                throw new RevocationServiceException(ErrorMessages.ENTITY_NOT_FOUND + exception.getMessage());
            }
            revocationRequestData.setEntity(entityData);
        }
        revocationRequestData.setCrlEntryExtensionsJSONData(JsonUtil.getJsonFromObject(revocationRequest.getCrlEntryExtensions()));
        try {
            for (final Certificate certificate : revocationRequest.getCertificatesToBeRevoked()) {
                final CertificateAuthorityData issuerCertificateAuthorityData = persistenceManager.findEntityByName(CertificateAuthorityData.class, certificate.getIssuer().getName(),
                        Constants.NAME_PATH);
                final Map<String, Object> mapCertificate = new HashMap<>();
                mapCertificate.put("serialNumber", certificate.getSerialNumber());
                mapCertificate.put("issuerCA", issuerCertificateAuthorityData);
                final CertificateData certificateData = persistenceManager.findEntitiesByAttributes(CertificateData.class, mapCertificate).get(0);
                certificateDataset.add(certificateData);
            }
        } catch (final PersistenceException exception) {
            logger.error(ErrorMessages.ENTITY_NOT_FOUND, exception);
            throw new RevocationServiceException(ErrorMessages.ENTITY_NOT_FOUND + exception.getMessage());
        }
        revocationRequestData.setCertificatesToRevoke(certificateDataset);
        return revocationRequestData;
    }
}
