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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;

import java.util.*;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;

public class EntitySetUpData {

    private static final String entityName = "ENMSecurity";

    /**
     * Prepares {@link EntityInfoData} to check for equals method.
     * 
     * @return {@link EntityInfoData} to compare.
     */
    public EntityInfoData getEntityForEqual() {

        final EntityInfoData entityInfoData = new EntityInfoData();
        final Set<CertificateRequestData> certificateRequestDatas = new HashSet<CertificateRequestData>();
        certificateRequestDatas.add(new CertificateRequestSetUpData().getCSRForEqual());

        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(new CertificateSetUpData().getCertificateForEqual());

        entityInfoData.setId(1);
        entityInfoData.setName(entityName);
        entityInfoData.setoTP("Sample_OTP");
        entityInfoData.setoTPCount(new Integer(5));
        entityInfoData.setStatus(EntityStatus.NEW);
        entityInfoData.setCreatedDate(new Date("1/01/2016"));
        entityInfoData.setModifiedDate(new Date("1/12/2016"));
        entityInfoData.setSubjectDN(new SubjectSetUpData().getSubjectForCreate().toASN1String());
        entityInfoData.setSubjectAltName(JsonUtil.getJsonFromObject(new SubjectAltNameSetUpData().getSANForCreate()));
        entityInfoData.setCertificateDatas(certificateDatas);
        return entityInfoData;
    }

    /**
     * Prepares {@link EntityInfoData} to check for equals method.
     * 
     * @return {@link EntityInfoData} to compare.
     */
    public EntityInfoData getEntityForNotEqual() {

        final EntityInfoData entityInfoData = new EntityInfoData();

        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(new CertificateSetUpData().getCertificateForNotEqual());

        entityInfoData.setId(2);
        entityInfoData.setName(entityName);
        entityInfoData.setoTP("Sample_OTP");
        entityInfoData.setoTPCount(new Integer(5));
        entityInfoData.setStatus(EntityStatus.DELETED);
        entityInfoData.setCreatedDate(new Date("2/01/2016"));
        entityInfoData.setModifiedDate(new Date("2/12/2016"));
        entityInfoData.setSubjectDN(new SubjectSetUpData().getSubjectForCreate().toASN1String());
        entityInfoData.setSubjectAltName(JsonUtil.getJsonFromObject(new SubjectAltNameSetUpData().getSANForCreate()));
        entityInfoData.setCertificateDatas(certificateDatas);
        return entityInfoData;
    }
}
