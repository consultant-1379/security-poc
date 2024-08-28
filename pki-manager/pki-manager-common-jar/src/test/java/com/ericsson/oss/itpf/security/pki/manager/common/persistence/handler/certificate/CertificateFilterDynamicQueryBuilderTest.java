package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import static org.junit.Assert.assertEquals;

import java.text.SimpleDateFormat;
import java.util.*;

import org.junit.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.FilterResponseType;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;

@RunWith(MockitoJUnitRunner.class)
public class CertificateFilterDynamicQueryBuilderTest {

    @Mock
    private Logger logger;

    @InjectMocks
    CertificateFilterDynamicQueryBuilder certificateFilterDynamicQueryBuilder;

    private final static CertificateStatus certificatestatus = CertificateStatus.ACTIVE;

    CertificateFilter certificateFilter;

    @Before
    public void setUp() {
        certificateFilter = new CertificateFilter();
        Long[] certificateIdList = new Long[1];
        for (int i = 0; i < 1; i++) {
            certificateIdList[i] = (long) 1;
        }
        CertificateStatus[] certificateStatusList = new CertificateStatus[1];
        for (int i = 0; i < 1; i++) {
            certificateStatusList[i] = certificatestatus;
        }
        certificateFilter.setCertificateStatusList(certificateStatusList);
        certificateFilter.setCertificateIdList(certificateIdList);
        certificateFilter.setIssuerDN("MyRoot");
        certificateFilter.setSubjectDN("MyRoot");
        final SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd-MM-yyyy");
        Date date = new Date();
        Date date1 = new Date();
        try {
            date = simpleDateFormat.parse("01-01-2013");
            date1 = simpleDateFormat.parse("06-15-2013");

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        certificateFilter.setExpiryDateFrom(date);
        certificateFilter.setExpiryDateTo(date1);
    }

    @Test
    public void testWhere() {

        final StringBuilder actualDymanicQuery = new StringBuilder();
        final StringBuilder expectedDymanicQuery = new StringBuilder(
                "WHERE  c.id IN (1)  and c.subject_dn LIKE :subjectDN and issuercert.subject_dn LIKE :issuerDN and date(c.not_after) >= :expiryDateFrom and date(c.not_after) <= :expiryDateTo and  c.status_id IN (1)");

        certificateFilterDynamicQueryBuilder.where(certificateFilter, actualDymanicQuery);

        assertEquals(expectedDymanicQuery.toString().trim(), actualDymanicQuery.toString().trim());
    }

    @Test
    public void testGetResultSet() {

        final StringBuilder actualDymanicQuery = new StringBuilder();
        final EnumSet<EntityType> entityTypeFilter = EnumSet.of(EntityType.CA_ENTITY);
        actualDymanicQuery.append("SELECT c.* from certificate c  LEFT JOIN ca_certificate cc on c.id = cc.certificate_id   LEFT JOIN caentity ca on ca.id = cc.ca_id ");

        final StringBuilder expectedDymanicQuery = certificateFilterDynamicQueryBuilder.replaceQueryString(entityTypeFilter, actualDymanicQuery, FilterResponseType.COUNT);
        Assert.assertTrue(expectedDymanicQuery.toString().contains("COUNT(*)"));
    }

    @Test
    public void testBuildCACertificatesQuery() {

        final StringBuilder actualDymanicQuery = new StringBuilder();
        final EnumSet<EntityType> entityTypeFilter = EnumSet.of(EntityType.CA_ENTITY);
        actualDymanicQuery
                .append("SELECT c.* from certificate c  JOIN ca_certificate cc on c.id = cc.certificate_id   JOIN caentity ca on ca.id = cc.ca_id and ca.is_external_ca=false  LEFT JOIN certificate issuercert on issuercert.id = c.issuer_certificate_id  WHERE c.subject_dn LIKE :subjectDN and issuercert.subject_dn LIKE :issuerDN and date(c.not_after) >= :expiryDateFrom and date(c.not_after) <= :expiryDateTo and  c.status_id IN (1)");

        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("issuerDN", certificateFilter.getIssuerDN());
        parameters.put("ACTIVE", certificateFilter.getCertificateStatusList());
        certificateFilter.setCertificateIdList(null);

        final StringBuilder expectedDymanicQuery = certificateFilterDynamicQueryBuilder.buildCACertificatesQuery(certificateFilter, entityTypeFilter, parameters);

        System.out.println(expectedDymanicQuery);

        assertEquals(expectedDymanicQuery.toString().trim(), actualDymanicQuery.toString().trim());
    }

    @Test
    public void testBuildEntityCertificatesQuery() {

        final StringBuilder actualDymanicQuery = new StringBuilder();
        final EnumSet<EntityType> entityTypeFilter = EnumSet.of(EntityType.ENTITY);
        actualDymanicQuery
                .append("SELECT c.* from certificate c  WHERE  c.id IN (1)  and c.subject_dn LIKE :subjectDN and issuercert.subject_dn LIKE :issuerDN and date(c.not_after) >= :expiryDateFrom and date(c.not_after) <= :expiryDateTo and  c.status_id IN (1)");

        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("issuerDN", certificateFilter.getIssuerDN());
        parameters.put("ACTIVE", certificateFilter.getCertificateStatusList());

        final StringBuilder expectedDymanicQuery = certificateFilterDynamicQueryBuilder.buildEntityCertificatesQuery(certificateFilter, entityTypeFilter, parameters);
        System.out.println(expectedDymanicQuery);

        assertEquals(expectedDymanicQuery.toString().trim(), actualDymanicQuery.toString().trim());
    }

    @Test
    public void testBuildCAAndEntityCertificatesListQuery() {

        final StringBuilder actualDymanicQuery = new StringBuilder();
        final EnumSet<EntityType> entityTypeFilter = EnumSet.of(EntityType.ENTITY);
        actualDymanicQuery
                .append("SELECT uniontable.*  FROM ( (SELECT c.* from certificate c  WHERE  c.id IN (1)  and c.subject_dn LIKE :subjectDN and issuercert.subject_dn LIKE :issuerDN and date(c.not_after) >= :expiryDateFrom and date(c.not_after) <= :expiryDateTo and  c.status_id IN (1) ) UNION (SELECT c.* from certificate c  WHERE  c.id IN (1)  and c.subject_dn LIKE :subjectDN and issuercert.subject_dn LIKE :issuerDN and date(c.not_after) >= :expiryDateFrom and date(c.not_after) <= :expiryDateTo and  c.status_id IN (1) ) ) as uniontable ");

        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("issuerDN", certificateFilter.getIssuerDN());
        parameters.put("ACTIVE", certificateFilter.getCertificateStatusList());

        final StringBuilder expectedDymanicQuery = certificateFilterDynamicQueryBuilder.buildCAAndEntityCertificatesQuery(certificateFilter, entityTypeFilter, FilterResponseType.LIST, parameters);

        assertEquals(expectedDymanicQuery.toString().trim(), actualDymanicQuery.toString().trim());
    }

    @Test
    public void testBuildCAAndEntityCertificatesCountQuery() {

        final StringBuilder actualDymanicQuery = new StringBuilder();
        final EnumSet<EntityType> entityTypeFilter = EnumSet.of(EntityType.ENTITY);
        actualDymanicQuery
                .append("SELECT COUNT(*)  FROM ((SELECT c.* from certificate c  WHERE  c.id IN (1)  and c.subject_dn LIKE :subjectDN and issuercert.subject_dn LIKE :issuerDN and date(c.not_after) >= :expiryDateFrom and date(c.not_after) <= :expiryDateTo and  c.status_id IN (1) ) UNION (SELECT c.* from certificate c  WHERE  c.id IN (1)  and c.subject_dn LIKE :subjectDN and issuercert.subject_dn LIKE :issuerDN and date(c.not_after) >= :expiryDateFrom and date(c.not_after) <= :expiryDateTo and  c.status_id IN (1) ) ) as uniontable ");

        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("issuerDN", certificateFilter.getIssuerDN());
        parameters.put("ACTIVE", certificateFilter.getCertificateStatusList());

        final StringBuilder expectedDymanicQuery = certificateFilterDynamicQueryBuilder.buildCAAndEntityCertificatesQuery(certificateFilter, entityTypeFilter, FilterResponseType.COUNT, parameters);

        assertEquals(expectedDymanicQuery.toString().trim(), actualDymanicQuery.toString().trim());
    }

    @Test
    public void testBuildCertificatesQuery() {

        final StringBuilder actualDymanicQuery = new StringBuilder();
        final EnumSet<EntityType> entityTypeFilter = EnumSet.of(EntityType.ENTITY);
        actualDymanicQuery
                .append("SELECT c.* from certificate c  WHERE  c.id IN (1)  and c.subject_dn LIKE :subjectDN and issuercert.subject_dn LIKE :issuerDN and date(c.not_after) >= :expiryDateFrom and date(c.not_after) <= :expiryDateTo and  c.status_id IN (1)  ORDER BY issued_time DESC");

        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("issuerDN", certificateFilter.getIssuerDN());
        parameters.put("ACTIVE", certificateFilter.getCertificateStatusList());

        final StringBuilder expectedDymanicQuery = certificateFilterDynamicQueryBuilder.buildCertificatesQuery(certificateFilter, entityTypeFilter, FilterResponseType.LIST, parameters);

        assertEquals(expectedDymanicQuery.toString().trim(), actualDymanicQuery.toString().trim());
    }
}
