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

package com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test;

import java.util.Date;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;

public class BaseTest {

    private static CertificateAuthorityData certificateAuthorityData;
    private static CertificateAuthority certificateAuthority;
    private static RevocationRequestData revocationRequestData;
    private static RevocationRequest revocationRequest;
    private static CertificateData certificateData;
    private static Certificate certificate;
    private static EntityInfoData entityInfoData;
    private static EntityInfo entityInfo;

    /**
     * Prepare CertificateAuthorityData JPA object
     * 
     * @param id
     *            - CaEntity id
     * @param CaName
     *            - Name Of CaEntity
     * @return - CertificateAuthorityData JPA
     */
    protected CertificateAuthorityData prepareCertificateAuthorityData(long id, String CaName) {
        certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setId(id);
        certificateAuthorityData.setName(CaName);
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
        return certificateAuthorityData;
    }

    /**
     * Prepare CertificateAuthority API object
     * 
     * @param id
     *            - CaEntity id
     * @param CaName
     *            - Name Of CaEntity
     * @return - CertificateAuthority model
     */
    protected CertificateAuthority prepareCertificateAuthority(long id, String CaName) {
        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(id);
        certificateAuthority.setName(CaName);
        certificateAuthority.setRootCA(false);
        certificateAuthority.setStatus(CAStatus.ACTIVE);
        return certificateAuthority;
    }

    /**
     * Prepare RevocationRequestData JPA object for CA entity
     * 
     * @return RevocationRequestData object
     */
    protected RevocationRequestData prepareRevocationRequestDataWithCaEntity() {
        revocationRequestData = new RevocationRequestData();
        revocationRequestData.setCaEntity(prepareCertificateAuthorityData(101, "ENMSUBCA"));
        revocationRequestData.setEntity(null);

        CrlEntryExtensions crlEntryExtensions = getCrlEntryExtensions(RevocationReason.KEY_COMPROMISE);

        revocationRequestData.setCrlEntryExtensionsJSONData(JsonUtil.getJsonFromObject(crlEntryExtensions));

        revocationRequestData.setStatus(RevocationRequestStatus.NEW);
        return revocationRequestData;
    }

    /**
     * Prepare RevocationRequestData API model for entity
     * 
     * @return RevocationRequestData object
     */
    protected RevocationRequestData prepareRevocationRequestDataWithEntity() {
        revocationRequestData = new RevocationRequestData();
        revocationRequestData.setCaEntity(null);
        revocationRequestData.setEntity(prepareEntityInfoData(1001, "Entity1"));

        CrlEntryExtensions crlEntryExtensions = getCrlEntryExtensions(RevocationReason.KEY_COMPROMISE);

        revocationRequestData.setCrlEntryExtensionsJSONData(JsonUtil.getJsonFromObject(crlEntryExtensions));
        revocationRequestData.setStatus(RevocationRequestStatus.NEW);
        return revocationRequestData;
    }

    /**
     * Prepare EntityInfoData JPA object
     * 
     * @param id
     *            - Entity id
     * @param entityName
     *            - Entity Name
     * @return - EntityInfoData JPA object
     */
    protected EntityInfoData prepareEntityInfoData(long id, String entityName) {
        entityInfoData = new EntityInfoData();
        entityInfoData.setId(id);
        entityInfoData.setName(entityName);
        entityInfoData.setStatus(EntityStatus.ACTIVE);
        return entityInfoData;
    }

    /**
     * Prepare EntityInfo API model
     * 
     * @param id
     *            - Entity id
     * @param entityName
     *            - Entity Name
     * @return - EntityInfo model
     */
    protected EntityInfo prepareEntityInfo(long id, String entityName) {
        entityInfo = new EntityInfo();
        entityInfo.setId(id);
        entityInfo.setName(entityName);
        entityInfo.setStatus(EntityStatus.ACTIVE);
        return entityInfo;
    }

    /**
     * Prepare RevocationRequest API model for CA entity
     * 
     * @return - RevocationRequest model
     */
    protected RevocationRequest prepareRevocationrequestForCaEntity() {
        revocationRequest = new RevocationRequest();
        revocationRequest.setCaEntity(prepareCertificateAuthority(101, "ENMSUBCA"));
        revocationRequest.setEntity(null);

        CrlEntryExtensions crlEntryExtensions = getCrlEntryExtensions(RevocationReason.AA_COMPROMISE);
        revocationRequest.setCrlEntryExtensions(crlEntryExtensions);

        return revocationRequest;
    }

    /**
     * Prepare RevocationRequest API model for entity
     * 
     * @return - RevocationRequest model
     */
    protected RevocationRequest prepareRevocationrequestForEntity() {
        revocationRequest = new RevocationRequest();
        revocationRequest.setCaEntity(null);
        revocationRequest.setEntity(prepareEntityInfo(1001, "Entity1"));

        CrlEntryExtensions crlEntryExtensions = getCrlEntryExtensions(RevocationReason.AA_COMPROMISE);
        revocationRequest.setCrlEntryExtensions(crlEntryExtensions);

        return revocationRequest;
    }

    private CrlEntryExtensions getCrlEntryExtensions(RevocationReason revocationReason) {
        CrlEntryExtensions crlEntryExtensions = new CrlEntryExtensions();

        InvalidityDate invalidityDateObject = new InvalidityDate();
        invalidityDateObject.setInvalidityDate(new Date());
        crlEntryExtensions.setInvalidityDate(invalidityDateObject);

        ReasonCode reasonCodeObject = new ReasonCode();
        reasonCodeObject.setRevocationReason(revocationReason);
        crlEntryExtensions.setReasonCode(reasonCodeObject);
        return crlEntryExtensions;
    }

    /**
     * Prepare CertificateData JPA object
     * 
     * @param id
     *            - Certificate id
     * @param serialNumber
     *            - Certificate SerialNumber
     * @return CertificateData JPA object
     */
    protected CertificateData prepareCertificateData(long id, String serialNumber) {
        certificateData = new CertificateData();
        certificateData.setId(id);
        certificateData.setSerialNumber(serialNumber);
        certificateData.setIssuerCA(prepareCertificateAuthorityData(555, "ENMROOTCA"));
        return certificateData;
    }

    /**
     * Prepare Certificate API model
     * 
     * @param id
     *            - Certificate id
     * @param serialNumber
     *            - Certificate SerialNumber
     * @return Certificate model
     */
    protected Certificate prepareCertificate(long id, String serialNumber) {
        certificate = new Certificate();
        certificate.setId(id);
        certificate.setSerialNumber(serialNumber);
        certificate.setIssuer(prepareCertificateAuthority(555, "ENMROOTCA"));
        return certificate;
    }

}
