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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension.CrlEntryExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * Converts API models to JPA models and vice versa.
 *
 * @author xvambur
 *
 */
public class RevocationRequestModelMapper {

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityMapper caEntityMapper;

    @Inject
    @EntityQualifier(EntityType.ENTITY)
    EntityMapper entityMapper;

    @Inject
    CertificateModelMapper certificateModelMapper;

    /**
     * Convert RevocationRequestData entity object to RevocationRequest object model.
     *
     * @param revocationRequestData
     *            is the RevocationRequestData that needs to be convert into object model
     * @return RevocationRequest - is revocationRequest object model
     * @throws IOException
     * @throws CertificateException
     */
    public RevocationRequest toAPIModel(final RevocationRequestData revocationRequestData) throws CertificateException, IOException {
        final RevocationRequest revocationRequest = new RevocationRequest();
        if (!(revocationRequestData.getCaEntity() == null)) {
            final CAEntity caEntity = caEntityMapper.toAPIFromModel(revocationRequestData.getCaEntity(), false);
            revocationRequest.setCaEntity(caEntity.getCertificateAuthority());
            revocationRequest.setEntity(null);
        } else {
            final Entity entity = entityMapper.toAPIFromModelForSummary(revocationRequestData.getEntity());
            revocationRequest.setEntity(entity.getEntityInfo());
            revocationRequest.setCaEntity(null);
        }
        final List<Certificate> certificateList = new ArrayList<Certificate>();
        for (final CertificateData certificateData : revocationRequestData.getCertificatesToRevoke()) {

            final Certificate certificate = certificateModelMapper.toObjectModel(certificateData, false);
            final CAEntity issuer = caEntityMapper.toAPIFromModel(certificateData.getIssuerCA(), false);
            certificate.setIssuer(issuer.getCertificateAuthority());
            certificateList.add(certificate);
        }
        revocationRequest.setCertificatesToBeRevoked(certificateList);
        revocationRequest.setCrlEntryExtensions(JsonUtil.getObjectFromJson(CrlEntryExtensions.class, revocationRequestData.getCrlEntryExtensionsJSONData()));
        return revocationRequest;
    }

    /**
     * Convert RevocationRequest Object model to RevocationRequestData entity object.
     *
     * @param revocationRequest
     *            - is the RevocationRequest object
     * @return RevocationRequestData - is the RevocationRequestData JPA object
     * @throws CertificateEncodingException
     */
    public RevocationRequestData fromAPIModel(final RevocationRequest revocationRequest) throws CertificateEncodingException, EntityServiceException, PersistenceException {
        final RevocationRequestData revocationRequestData = new RevocationRequestData();
        if (!(revocationRequest.getCaEntity() == null)) {
            final CAEntityData caEntityData = caEntityMapper.fromAPIToModel(revocationRequest.getCaEntity());
            revocationRequestData.setCaEntity(caEntityData);
            revocationRequest.setEntity(null);
        } else {
            final EntityData entity = entityMapper.fromAPIToModel(revocationRequest.getEntity());
            revocationRequestData.setEntity(entity);
            revocationRequestData.setCaEntity(null);
        }
        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        for (final Certificate certificate : revocationRequest.getCertificatesToBeRevoked()) {
            final CertificateData certificateData = certificateModelMapper.fromObjectModel(certificate);
            certificateDatas.add(certificateData);
        }
        revocationRequestData.setCertificatesToRevoke(certificateDatas);
        revocationRequestData.setCrlEntryExtensionsJSONData(JsonUtil.getJsonFromObject(revocationRequest.getCrlEntryExtensions()));
        return revocationRequestData;
    }
}
