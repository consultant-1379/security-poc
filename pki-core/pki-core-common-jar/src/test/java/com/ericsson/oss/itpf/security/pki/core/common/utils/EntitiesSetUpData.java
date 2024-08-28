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
package com.ericsson.oss.itpf.security.pki.core.common.utils;

import java.util.*;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;

public class EntitiesSetUpData {

    public final static String NAME_PATH = "name";
    public static final String ALGORITHM_KEY_SIZE = "keySize";
    public static final String ALGORITHM_TYPE = "type";
    public static final String NAME = "name";
    public static final int FAILURE = 1;
    public static final int SUCCESS = 0;

    EntityInfoData entityInfoData;
    CertificateAuthorityData certificateAuthorityData;

    EntityInfo entityInfo;
    CertificateAuthority certificateAuthority;

    Map<String, Object> entityInput = new HashMap<String, Object>();

    public EntitiesSetUpData() {

        entityInfoData = createEntityData();

        entityInfo = createEntityInfo();

        certificateAuthority = createCertificateAuthority();

        certificateAuthorityData = createCertificateAuthorityData();

    }

    private EntityInfoData createEntityData() {

        final EntityInfoData entityInfoData = new EntityInfoData();

        entityInfoData.setId(1);
        entityInfoData.setName("ENMService");
        entityInfoData.setSubjectAltName(JsonUtil.getJsonFromObject(createSAN()));
        entityInfoData.setSubjectDN(createSubject().toASN1String());

        return entityInfoData;

    }

    private CertificateAuthorityData createCertificateAuthorityData() {

        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        certificateAuthorityData.setId(1);
        certificateAuthorityData.setName("ENMRootCA");
        certificateAuthorityData.setSubjectDN(createSubject().toASN1String());
        certificateAuthorityData.setSubjectAltName(JsonUtil.getJsonFromObject(createSAN()));
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setStatus(CAStatus.NEW);

        return certificateAuthorityData;

    }

    private CertificateAuthority createCertificateAuthority() {

        final CertificateAuthority certificateAuthority = new CertificateAuthority();

        certificateAuthority.setId(1);
        certificateAuthority.setName("ENMRootCA");
        certificateAuthority.setRootCA(true);
        certificateAuthority.setSubject(createSubject());
        certificateAuthority.setSubjectAltName(createSAN());
        final CertificateAuthority issuer = new CertificateAuthority();
        issuer.setName(NAME);
        certificateAuthority.setIssuer(issuer);

        return certificateAuthority;
    }

    private EntityInfo createEntityInfo() {

        final EntityInfo entityInfo = new EntityInfo();

        entityInfo.setId(1);
        entityInfo.setName("ENMService");
        entityInfo.setSubject(createSubject());
        entityInfo.setSubjectAltName(createSAN());
        entityInfo.setOTP("Sample_OTP");
        entityInfo.setOTPCount(5);
        entityInfo.setStatus(EntityStatus.NEW);

        return entityInfo;

    }

    private Subject createSubject() {

        final Subject subject = new Subject();

        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField common_name = new SubjectField();
        common_name.setType(SubjectFieldType.COMMON_NAME);
        common_name.setValue("ERBS_node");

        final SubjectField organization = new SubjectField();
        organization.setType(SubjectFieldType.ORGANIZATION);
        organization.setValue("ENM");

        final SubjectField organizationUnit = new SubjectField();
        organizationUnit.setType(SubjectFieldType.ORGANIZATION_UNIT);
        organizationUnit.setValue("Ericsson");

        subjectFields.add(common_name);
        subjectFields.add(organization);
        subjectFields.add(organizationUnit);

        subject.setSubjectFields(subjectFields);

        return subject;

    }

    private SubjectAltName createSAN() {

        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        final SubjectAltNameField dns_name = new SubjectAltNameField();
        final SubjectAltNameField other_name = new SubjectAltNameField();
        final SubjectAltNameField edi_party_name = new SubjectAltNameField();

        final SubjectAltNameString dns_name_value = new SubjectAltNameString();
        dns_name_value.setValue("www.ericsson.com");

        dns_name.setType(SubjectAltNameFieldType.DNS_NAME);
        dns_name.setValue(dns_name_value);

        final EdiPartyName editPartyNanme = new EdiPartyName();
        editPartyNanme.setNameAssigner("EditPartyAssigner");
        editPartyNanme.setPartyName("EditPartyName");

        edi_party_name.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        edi_party_name.setValue(editPartyNanme);

        final OtherName otherName = new OtherName();
        otherName.setTypeId("1");
        otherName.setValue("otherName");

        other_name.setType(SubjectAltNameFieldType.OTHER_NAME);
        other_name.setValue(otherName);

        subjectAltNameFields.add(dns_name);
        subjectAltNameFields.add(edi_party_name);
        subjectAltNameFields.add(other_name);

        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;

    }

    /**
     * @return the entity
     */
    public EntityInfo getEntityInfo() {
        return entityInfo;
    }

    /**
     * @return the entityData
     */
    public EntityInfoData getEntityInfoData() {
        return entityInfoData;
    }

    /**
     * @return the caEntityData
     */
    public CertificateAuthorityData getCertificateAuthorityData() {
        return certificateAuthorityData;
    }

    /**
     * @return the caEntityData
     */
    public CertificateAuthority getCertificateAuthority() {
        return certificateAuthority;
    }

    /**
     * @return the input
     */
    public Map<String, Object> getInput() {
        return entityInput;
    }
}
