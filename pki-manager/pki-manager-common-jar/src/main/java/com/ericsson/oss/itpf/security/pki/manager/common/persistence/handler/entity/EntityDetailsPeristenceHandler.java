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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity;

import java.math.BigInteger;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntitiesModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

/**
 * This class is responsible for fetching both CAEntities and Entities combined together using UNION operation. This class contains methods to fetch the records by applying filter and without applying
 * filter.
 *
 * @author tcssote
 */
public class EntityDetailsPeristenceHandler {
    @Inject
    PersistenceManager persistenceManager;

    @Inject
    EntitiesModelMapperFactory entitiesModelMapperFactory;

    @Inject
    Logger logger;

    @Inject
    EntityFilterDynamicQueryBuilder entityFilterDynamicQueryBuilder;

    /**
     * This method returns the list of entitydetails fetched from database by applying filter/without filter
     *
     * @param entitiesFilter
     *            the searchCriteria variables using which the data has to be fetched
     * @return list of AbstractEntityDetails between given offset, limit values matching given criteria
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public List<AbstractEntityDetails> getEntityDetails(final EntitiesFilter entitiesFilter) throws EntityServiceException {
        final List<AbstractEntityDetails> entityDetailsList = new ArrayList<AbstractEntityDetails>();

        List<Object[]> entityDetails = new ArrayList<Object[]>();

        final StringBuilder dynamicQuery = new StringBuilder();

        final Map<String, Object> attributes = entityFilterDynamicQueryBuilder.build(entitiesFilter, dynamicQuery);

        try {

            logger.debug("Union Query with filter is: {}", dynamicQuery);
            entityDetails = persistenceManager.findEntitiesByNativeQuery(dynamicQuery.toString(), attributes, entitiesFilter.getOffset(), entitiesFilter.getLimit());

        } catch (final PersistenceException persistenceException) {
            logger.error("Unexpected Error in retrieving entities that match with filtered criteria {}. {}", entitiesFilter, persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + entitiesFilter, persistenceException);
        }

        if (ValidationUtils.isNullOrEmpty(entityDetails)) {
            return entityDetailsList;
        } else {
            return buildEntityDetailsObject(entityDetails, entityDetailsList);
        }

    }

    /**
     * This method builds the entitydetails object based on the result list from database. EntityDetails object contains type to distinguish whether the entitydetails object is caentity or entity.
     *
     * @param entityDetails
     *            list of results fetched from database
     * @param entityDetailsList
     *            list of entityDetails to be populated with result list
     * @return list of AbstractEntityDetails between given offset, limit values matching given criteria
     */
    private List<AbstractEntityDetails> buildEntityDetailsObject(final List<Object[]> entityDetails, final List<AbstractEntityDetails> entityDetailsList) {
        if (!ValidationUtils.isNullOrEmpty(entityDetails)) {
            for (final Object[] entityDetail : entityDetails) {
                final Algorithm algorithm = new Algorithm();
                if (entityDetail[8] != null) {
                    algorithm.setId(((BigInteger) entityDetail[8]).longValue());
                    algorithm.setKeySize((Integer) entityDetail[9]);
                    algorithm.setName((String) entityDetail[10]);
                    algorithm.setOid((String) entityDetail[11]);
                    algorithm.setSupported((Boolean) entityDetail[12]);
                    algorithm.setType(AlgorithmType.getType((Integer) entityDetail[13]));
                }

                final EntityProfile entityProfile = new EntityProfile();
                if (entityDetail[14] != null) {
                    entityProfile.setId(((BigInteger) entityDetail[14]).longValue());
                }
                entityProfile.setName((String) entityDetail[15]);

                if ((Boolean) entityDetail[16]) {
                    final CertificateAuthority certificateAuthority = new CertificateAuthority();
                    if (entityDetail[0] != null) {
                        certificateAuthority.setId(((BigInteger) entityDetail[0]).longValue());
                    }
                    certificateAuthority.setName((String) entityDetail[2]);
                    certificateAuthority.setSubject(toSubject((String) entityDetail[5]));
                    certificateAuthority.setSubjectAltName(toSubjectAltName((String) entityDetail[6]));
                    certificateAuthority.setStatus(CAStatus.getStatus((Integer) entityDetail[7]));
                    final List<Certificate> inActiveCertificates = new ArrayList<Certificate>();
                    int count = 0;
                    if (entityDetail[17] != null) {
                        count = ((BigInteger) entityDetail[17]).intValue();
                    }
                    for (int i = 0; i < count; i++) {
                        final Certificate certificate = new Certificate();
                        inActiveCertificates.add(certificate);
                    }

                    certificateAuthority.setInActiveCertificates(inActiveCertificates);
                    final CaEntityDetails caEntityDetails = new CaEntityDetails((boolean) entityDetail[1], entityProfile, algorithm, EntityType.CA_ENTITY, certificateAuthority);
                    entityDetailsList.add(caEntityDetails);
                } else {
                    final EntityInfo entityInfo = new EntityInfo();
                    if (entityDetail[0] != null) {
                        entityInfo.setId(((BigInteger) entityDetail[0]).longValue());
                    }
                    entityInfo.setName((String) entityDetail[2]);
                    entityInfo.setOTP((String) entityDetail[3]);
                    entityInfo.setOTPCount((Integer) entityDetail[4]);
                    entityInfo.setSubject(toSubject((String) entityDetail[5]));
                    entityInfo.setSubjectAltName(toSubjectAltName((String) entityDetail[6]));
                    entityInfo.setStatus(EntityStatus.getStatus((Integer) entityDetail[7]));
                    final List<Certificate> inActiveCertificates = new ArrayList<Certificate>();
                    int count = 0;
                    if (entityDetail[17] != null) {
                        count = ((BigInteger) entityDetail[17]).intValue();
                    }
                    for (int i = 0; i < count; i++) {
                        final Certificate certificate = new Certificate();
                        inActiveCertificates.add(certificate);
                    }

                    entityInfo.setInActiveCertificates(inActiveCertificates);
                    final EntityDetails endEntityDetails = new EntityDetails((boolean) entityDetail[1], entityProfile, algorithm, EntityType.ENTITY, entityInfo);
                    entityDetailsList.add(endEntityDetails);
                }

            }
        }
        return entityDetailsList;
    }

    /**
     * This method converts the Json string to SubjectAltName object
     *
     * @param subjectAltNameString
     *            json string fetched from database
     * @return SubjectAltName SubjectAltName object converted from json string using JsonUtil
     */
    private SubjectAltName toSubjectAltName(final String subjectAltNameString) {
        if (!ValidationUtils.isNullOrEmpty(subjectAltNameString)) {
            return JsonUtil.getObjectFromJson(SubjectAltName.class, subjectAltNameString);
        }

        return null;
    }

    /**
     * This method converts the ASN1String to Subject object
     *
     * @param subjectString
     *            ASN1String fetched from database
     * @return Subject Subject object converted from ASN1String
     */
    protected Subject toSubject(final String subjectString) {
        if (!ValidationUtils.isNullOrEmpty(subjectString)) {
            return new Subject().fromASN1String(subjectString);
        }

        return null;
    }

}