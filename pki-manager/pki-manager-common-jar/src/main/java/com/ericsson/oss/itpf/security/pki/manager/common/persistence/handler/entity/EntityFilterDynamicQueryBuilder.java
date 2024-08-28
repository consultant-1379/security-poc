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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity;

import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.DynamicQueryBuilder;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.EntityStatusUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;

/**
 * This class used for build query dynamically based on EntitiesFilter and other utility methods
 *
 */
public class EntityFilterDynamicQueryBuilder extends DynamicQueryBuilder {

    @Inject
    Logger logger;

    private final static String queryForCaEntitiesFetchByFilter = "select c.id as ID,c.publishCertificatetoTDPS,c.name,null \\:\\: text as otp,null \\:\\: integer as otpcount,c.subject_dn,c.subject_alt_name,c.status_id,a.id as algorithm_id,a.key_size,a.name as algorithm_name,a.oid,a.is_supported,a.type_id,p.id as profile_id,p.name as profile_name,true,coalesce(ca_cert.count, 0) as count, c.modified_date as TimeStamp from caentity c left join algorithm a on a.id=c.key_generation_algorithm_id inner join entityprofile p on p.id=c.entity_profile_id left join (select ca_id,count(certificate_id) as count from ca_certificate group by ca_id) ca_cert on ca_cert.ca_id=c.id ";
    private final static String queryForEntitiesFetchByFilter = "select e.id as ID,e.publishCertificatetoTDPS,e.name,e.otp,e.otp_count,e.subject_dn,e.subject_alt_name,e.status_id,a.id as algorithm_id,a.key_size,a.name as algorithm_name,a.oid,a.is_supported,a.type_id,p.id as profile_id,p.name as profile_name,false,coalesce(entity_cert.count, 0) as count, e.modified_date as TimeStamp from entity e left join algorithm a on a.id=e.key_generation_algorithm_id inner join entityprofile p on p.id=e.entity_profile_id left join (select entity_id,count(certificate_id) as count from entity_certificate group by entity_id) entity_cert on entity_cert.entity_id=e.id ";

    private static final String UNION = " UNION ";
    private static final String AND = " AND ";
    private static final String WHERE = " WHERE ";

    /**
     * @param EntitiesFilter
     *            The {@link EntitiesFilter}
     * @param dynamicQuery
     *            dynamic Query String
     * @return returns parameters appended with given Criterias
     *
     */
    public Map<String, Object> build(final EntitiesFilter entitiesFilter, final StringBuilder dynamicQuery) {
        return union(entitiesFilter, dynamicQuery);
    }

    private Map<String, Object> union(final EntitiesFilter entitiesFilter, final StringBuilder dynamicQuery) {
        Map<String, Object> parameters = new HashMap<String, Object>();
        final List<String> clauses = new ArrayList<String>();

        if (entitiesFilter.getType().contains(EntityType.CA_ENTITY)) {
            final StringBuilder whereQueryForCA = new StringBuilder();
            parameters = buildWhereQueryForCA(entitiesFilter, whereQueryForCA, parameters);
            clauses.add(queryForCaEntitiesFetchByFilter + whereQueryForCA);
        }

        if (entitiesFilter.getType().contains(EntityType.ENTITY)) {
            final StringBuilder whereQueryForEE = new StringBuilder();
            parameters = buildWhereQueryForEE(entitiesFilter, whereQueryForEE, parameters);
            clauses.add(queryForEntitiesFetchByFilter + whereQueryForEE);
        }

        dynamicQuery.append(addCriterias(clauses.toArray(new String[0]), UNION)).append(" order by TimeStamp DESC");

        logger.debug("Final query is {}", dynamicQuery);
        logger.debug("The parameters are {}", parameters);

        return parameters;
    }

    private Map<String, Object> buildWhereQueryForCA(final EntitiesFilter entitiesFilter, final StringBuilder whereQueryForCA, final Map<String, Object> parameters) {
        final List<String> clauses = new ArrayList<String>();

        if (!ValidationUtils.isNullOrEmpty(entitiesFilter.getName())) {
            addCriteria("c.name", "ILIKE", entitiesFilter.getName(), "caName", clauses, parameters);
        }
        if (!ValidationUtils.isNullOrEmpty(entitiesFilter.getStatus())) {
            clauses.add(" c.status_id IN (:caStatusList)");
            parameters.put("caStatusList", EntityStatusUtils.getCAEntityStatusList(entitiesFilter));
        }
        if (!ValidationUtils.isNullOrEmpty(entitiesFilter.getCertificateAssigned())) {
            clauses.add(" (select count(certificate_id) from  ca_certificate ca_cert where ca_cert.ca_id=c.id)= :caCertificateCount ");
            parameters.put("caCertificateCount", entitiesFilter.getCertificateAssigned());
        }

        if (!clauses.isEmpty()) {
            whereQueryForCA.append(WHERE).append(addCriterias(clauses.toArray(new String[0]), AND));
        }
        return parameters;
    }

    public Map<String, Object> buildWhereQueryForEE(final EntitiesFilter entitiesFilter, final StringBuilder whereQueryForEE, final Map<String, Object> parameters) {
        final List<String> clauses = new ArrayList<String>();

        if (!ValidationUtils.isNullOrEmpty(entitiesFilter.getName())) {
            addCriteria("e.name", "ILIKE", entitiesFilter.getName(), "entityName", clauses, parameters);
        }
        if (!ValidationUtils.isNullOrEmpty(entitiesFilter.getStatus())) {
            clauses.add(" e.status_id IN (:statusList)");
            parameters.put("statusList", EntityStatusUtils.getEntityStatusList(entitiesFilter));
        }
        if (!ValidationUtils.isNullOrEmpty(entitiesFilter.getCertificateAssigned())) {
            clauses.add(" (select count(certificate_id) from  entity_certificate entity_cert where entity_cert.entity_id=e.id)= :entityCertificateCount ");
            parameters.put("entityCertificateCount", entitiesFilter.getCertificateAssigned());
        }

        if (!clauses.isEmpty()) {
            whereQueryForEE.append(WHERE).append(addCriterias(clauses.toArray(new String[0]), AND));
        }
        return parameters;
    }
}
