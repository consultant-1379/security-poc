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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import java.util.List;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * This helper class contains common methods that are used by CAEntity and Entity CertificateManager.
 */
public class CertificateHelper {

    @Inject
    Logger logger;

    @Inject
    CACertificatePersistenceHelper caPersistenceHelper;

    /**
     * Get Key Generation Algorithm from entity if exists. otherwise it will check in profiles.
     * 
     * @param abstractEntity
     *            The Entity Object.
     * @throws InvalidCAException
     *             Thrown if Multiple KeyGeneration Algorithms Provided.
     */
    public Algorithm getKeyGenerationAlgorithm(final AbstractEntity abstractEntity) throws InvalidCAException {

        Algorithm entityKeyGenerationAlgorithm = null;

        if (abstractEntity instanceof CAEntity) {
            final CAEntity caEntity = (CAEntity) abstractEntity;
            entityKeyGenerationAlgorithm = caEntity.getKeyGenerationAlgorithm();
        }

        else {
            final Entity entity = (Entity) abstractEntity;
            entityKeyGenerationAlgorithm = entity.getKeyGenerationAlgorithm();
        }

        if (entityKeyGenerationAlgorithm != null) {
            return entityKeyGenerationAlgorithm;
        }

        final Algorithm entityProfileKeyGenerationAlgorithm = abstractEntity.getEntityProfile().getKeyGenerationAlgorithm();

        if (entityProfileKeyGenerationAlgorithm != null) {
            return entityProfileKeyGenerationAlgorithm;
        }

        final List<Algorithm> certificateProfileKeyGenerationAlgorithm = abstractEntity.getEntityProfile().getCertificateProfile().getKeyGenerationAlgorithms();

        if (certificateProfileKeyGenerationAlgorithm.size() > 1) {
            throw new InvalidCAException(ErrorMessages.MULTIPLE_KEY_GENERATION_ALGORTITHM);
        }
        return certificateProfileKeyGenerationAlgorithm.get(0);
    }

    /**
     * Get Issuer CertificateData
     * 
     * @param certificateDatas
     *            set of certificateDatas
     * @param serialNumber
     *            is CA Certificate serial number.
     * @return Issuer {@link CertificateData}
     */
    public CertificateData getMappedCertificateData(final Set<CertificateData> certificateDatas, final String serialNumber) {
        CertificateData certificateData = null;
        for (final CertificateData certData : certificateDatas) {
            if (serialNumber != null) {
                if (serialNumber.equals(certData.getSerialNumber())) {
                    certificateData = certData;
                }
            } else {
                certificateData = certData;
            }
            if(certificateData != null){
                break;
            }
        }
        return certificateData;
    }

}
