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

import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.DynamicQueryBuilder;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.EntityTypeFilter;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.FilterResponseType;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;

/**
 * This class used for build query dynamically based on CertificateFilter and other utility methods
 *
 */
public class CertificateFilterDynamicQueryBuilder extends DynamicQueryBuilder {

    /**
     * @param certificateFilter
     *            The {@link CertificateFilter}
     * @param dynamicQuery
     *            dynamic Query String
     * @return returns dynamicQuery appended with given Criterias
     */
    public Map<String, Object> where(final CertificateFilter certificateFilter, final StringBuilder dynamicQuery) {
        final List<String> clauses = new ArrayList<String>();
        final Map<String, Object> parameters = new HashMap<String, Object>();

        if (certificateFilter.getCertificateIdList() != null && certificateFilter.getCertificateIdList().length > 0) {
            clauses.add(" c.id IN " + inOperatorValues(certificateFilter.getCertificateIdList()) + " ");
        }

        if (certificateFilter.getSubjectDN() != null) {
            addCriteria("c.subject_dn", "LIKE", certificateFilter.getSubjectDN().replaceAll("_", "\\_"), "subjectDN", clauses, parameters);
        }

        if (certificateFilter.getIssuerDN() != null) {
            addCriteria("issuercert.subject_dn", "LIKE", certificateFilter.getIssuerDN().replaceAll("_", "\\_"), "issuerDN", clauses, parameters);
        }

        if (certificateFilter.getExpiryDateFrom() != null) {
            addCriteria("date(c.not_after)", ">=", certificateFilter.getExpiryDateFrom(), "expiryDateFrom", clauses, parameters);
        }

        if (certificateFilter.getExpiryDateTo() != null) {
            addCriteria("date(c.not_after)", "<=", certificateFilter.getExpiryDateTo(), "expiryDateTo", clauses, parameters);
        }

        if (certificateFilter.getCertificateStatusList() != null && certificateFilter.getCertificateStatusList().length > 0) {
            clauses.add(" c.status_id IN " + inOperatorValues(getCertificateStatusArray(certificateFilter.getCertificateStatusList())) + " ");
        }

        if (!clauses.isEmpty()) {
            dynamicQuery.append(" WHERE ").append(addCriterias(clauses.toArray(new String[0]), " and "));
        }
        return parameters;
    }

    /**
     * @param certificateFilter
     *            The {@link CertificateFilter}
     * @param dynamicQuery
     *            dynamic Query String
     * @return returns dynamicQuery appended with given Criterias
     */
    public Map<String, Object> where(final DNBasedCertificateIdentifier dnBasedCertificateIdentifier, final StringBuilder dynamicQuery) {
        final List<String> clauses = new ArrayList<String>();
        final Map<String, Object> parameters = new HashMap<String, Object>();

        if (dnBasedCertificateIdentifier.getSubjectDN() != null) {
            addCriteria("cert.subjectDN", "=", dnBasedCertificateIdentifier.getSubjectDN(), "subjectDN", clauses, parameters);
        }

        if (dnBasedCertificateIdentifier.getIssuerDN() != null) {
            addCriteria("issuercert.subjectDN", "=", dnBasedCertificateIdentifier.getIssuerDN(), "issuerDN", clauses, parameters);
        }

        if (dnBasedCertificateIdentifier.getCerficateSerialNumber() != null) {
            addCriteria("cert.serialNumber", "=", dnBasedCertificateIdentifier.getCerficateSerialNumber(), "serial_number", clauses, parameters);
        } else {
            addCriteria("cert.status", "=", CertificateStatus.ACTIVE.getId(), "status_id", clauses, parameters);
        }

        if (!clauses.isEmpty()) {
            dynamicQuery.append(" WHERE ").append(addCriterias(clauses.toArray(new String[0]), " and "));
        }
        return parameters;
    }

    /**
     * Convert {@link CertificateStatus} array to Integer Array
     * 
     * @param certificateStatusArray
     *            {@link CertificateStatus} Array
     * @return Integer Array
     */
    public Integer[] getCertificateStatusArray(final CertificateStatus[] certificateStatusArray) {
        if (certificateStatusArray == null || certificateStatusArray.length == 0) {
            return new Integer[0];
        }
        Integer[] certStatusArray = new Integer[certificateStatusArray.length];
        for (int i = 0; i < certificateStatusArray.length; i++) {
            certStatusArray[i] = certificateStatusArray[i].getId();
        }
        return certStatusArray;
    }

    /**
     * Build dynamic query for CA certificates
     * 
     * @param certificateFilter
     *            The {@link CertificateFilter}
     * @param entityTypeFilter
     *            The entityTypeFilter is specifies CA_ENTITY/ENTITY/BOTH.
     * @param parameters
     *            The query parameters map
     * @return dynamicQuery for CA certificates
     */
    public StringBuilder buildCACertificatesQuery(final CertificateFilter certificateFilter, final EnumSet<EntityType> entityTypeFilter, final Map<String, Object> parameters) {

        final StringBuilder dynamicQuery = new StringBuilder();

        dynamicQuery.append("SELECT c.* from certificate c ");

        if (certificateFilter.getCertificateIdList() == null) {
            dynamicQuery.append(" JOIN ca_certificate cc on c.id = cc.certificate_id  ");
            dynamicQuery.append(" JOIN caentity ca on ca.id = cc.ca_id and ca.is_external_ca=false ");
        }

        //TODO : LEFT JOIN not needed, as it is not fetching Root CA if issuer_dn is given same as the given RootCA. This has to be removed and tested thoroughly
        if (certificateFilter.getCertificateIdList() == null && certificateFilter.getIssuerDN() != null) {
            dynamicQuery.append(" LEFT JOIN certificate issuercert on issuercert.id = c.issuer_certificate_id ");
        }
        parameters.putAll(where(certificateFilter, dynamicQuery));

        return dynamicQuery;
    }

    /**
     * Build dynamic query for Entity certificates
     * 
     * @param certificateFilter
     *            The {@link CertificateFilter}
     * @param entityTypeFilter
     *            The entityTypeFilter is specifies CA_ENTITY/ENTITY/BOTH.
     * @param responseType
     *            Query build with responseType LIST/COUNT
     * @param parameters
     *            The query parameters map
     * @return returns dynamicQuery for Entity certificates
     */
    public StringBuilder buildEntityCertificatesQuery(final CertificateFilter certificateFilter, final EnumSet<EntityType> entityTypeFilter, final Map<String, Object> parameters) {

        final StringBuilder dynamicQuery = new StringBuilder();

        dynamicQuery.append("SELECT c.* from certificate c ");

        if (certificateFilter.getCertificateIdList() == null) {
            dynamicQuery.append(" JOIN entity_certificate ec on ec.certificate_id = c.id");
            dynamicQuery.append(" JOIN entity e on e.id = ec.entity_id ");
        }

        //TODO : LEFT JOIN not needed, as it is not fetching Root CA if issuer_dn is given same as the given RootCA. This has to be removed and tested thoroughly
        if (certificateFilter.getCertificateIdList() == null && certificateFilter.getIssuerDN() != null) {
            dynamicQuery.append(" LEFT JOIN certificate issuercert on issuercert.id = c.issuer_certificate_id ");
        }
        parameters.putAll(where(certificateFilter, dynamicQuery));

        return dynamicQuery;
    }

    /**
     * Build dynamic query for CA and Entity certificates
     * 
     * @param certificateFilter
     *            The {@link CertificateFilter}
     * @param entityTypeFilter
     *            The entityTypeFilter is specifies CA_ENTITY/ENTITY/BOTH.
     * @param responseType
     *            Query build with responseType LIST/COUNT
     * @param parameters
     *            The query parameters map
     * 
     * @return returns dynamicQuery for CA and Entity certificates
     */
    public StringBuilder buildCAAndEntityCertificatesQuery(final CertificateFilter certificateFilter, final EnumSet<EntityType> entityTypeFilter, final FilterResponseType responseType,
            final Map<String, Object> parameters) {

        final StringBuilder dynamicQuery = new StringBuilder();

        if (responseType == FilterResponseType.LIST) {
            dynamicQuery.append("SELECT uniontable.*  FROM ( ");
        } else if (responseType == FilterResponseType.COUNT) {
            dynamicQuery.append("SELECT COUNT(*)  FROM (");
        }

        dynamicQuery.append("(").append(buildCACertificatesQuery(certificateFilter, entityTypeFilter, parameters)).append(")").append(" UNION ").append("(")
                .append(buildEntityCertificatesQuery(certificateFilter, entityTypeFilter, parameters)).append(")").append(" ) as uniontable ");
        return dynamicQuery;
    }

    /**
     * Build dynamic query for CA and Entity certificates
     * 
     * @param certificateFilter
     *            The {@link CertificateFilter}
     * @param entityTypeFilter
     *            The entityTypeFilter is specifies CA_ENTITY/ENTITY/BOTH.
     * @param responseType
     *            Query build with responseType LIST/COUNT
     * @param parameters
     *            The query parameters map
     * 
     * @return returns dynamicQuery for CA and Entity certificates
     */
    public StringBuilder buildCertificatesQuery(final CertificateFilter certificateFilter, final EnumSet<EntityType> entityTypeFilter, final FilterResponseType responseType,
            final Map<String, Object> parameters) {
        StringBuilder dynamicQuery = null;

        if (entityTypeFilter.containsAll(EntityTypeFilter.CAANDENTITY.getEntityTypeSet())) {
            dynamicQuery = buildCAAndEntityCertificatesQuery(certificateFilter, entityTypeFilter, responseType, parameters);
        } else if (entityTypeFilter.contains(EntityType.CA_ENTITY)) {
            dynamicQuery = buildCACertificatesQuery(certificateFilter, entityTypeFilter, parameters);
        } else if (entityTypeFilter.contains(EntityType.ENTITY)) {
            dynamicQuery = buildEntityCertificatesQuery(certificateFilter, entityTypeFilter, parameters);
        } else {
            dynamicQuery = new StringBuilder();
            return dynamicQuery;
        }
        if (responseType == FilterResponseType.LIST) {
            dynamicQuery.append(orderBy("issued_time", "DESC"));
        }
        return dynamicQuery;
    }

    /**
     * For CAEntity / Entity Certificates filter for count, replace c.* with count(*)
     * 
     * @param entityTypeFilter
     *            Entity Filter
     * @param dynamicQuery
     *            build dynamicQuery
     * @param responseType
     *            Query build with responseType LIST/COUNT
     * 
     * @return returns dynamicQuery for count, replace c.* with count(*)
     */
    public StringBuilder replaceQueryString(final EnumSet<EntityType> entityTypeFilter, StringBuilder dynamicQuery, final FilterResponseType responseType) {

        if (!(entityTypeFilter.containsAll(EntityTypeFilter.CAANDENTITY.getEntityTypeSet())) && responseType == FilterResponseType.COUNT) {
            dynamicQuery = new StringBuilder(dynamicQuery.toString().replace("c.*", "COUNT(*)"));
        }
        return dynamicQuery;
    }

}
