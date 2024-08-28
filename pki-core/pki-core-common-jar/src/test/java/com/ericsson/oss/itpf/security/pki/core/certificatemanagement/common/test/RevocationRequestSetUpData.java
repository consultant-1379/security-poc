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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;


import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.HashSet;
import java.util.Set;

import org.mockito.InjectMocks;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequestStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;

/**
 * To setup data for revocation request
 * @author tcsviku
 *
 */
public class RevocationRequestSetUpData {
    private Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
    private CertificateData certificateData;
    private CertificateAuthorityData certificateAuthorityData;
    private String crlEntryExtensionsJSONData="crl_entry_extensions";
    private EntityInfoData entityInfoData;

    
    /**
     * Prepares RevocationRequestData to check for equals method.
     * @return RevocationRequestData
     */
    public RevocationRequestData getRevocationRequestForEqual() {
        
        
        final RevocationRequestData revocationRequestData = new RevocationRequestData();
        certificateAuthorityData= new CertificateAuthoritySetUpData().getCertificateAuthotityForEqual();
        entityInfoData =new EntitySetUpData().getEntityForEqual();
        certificateData =new CertificateSetUpData().getCertificateForEqual();
        certificateDatas.add(certificateData);
        revocationRequestData.setId(5);
        revocationRequestData.setCaEntity(certificateAuthorityData);
        revocationRequestData.setCertificatesToRevoke(certificateDatas);
        revocationRequestData.setCrlEntryExtensionsJSONData(crlEntryExtensionsJSONData);
        revocationRequestData.setEntity(entityInfoData);
        revocationRequestData.setStatus(RevocationRequestStatus.NEW);

        return revocationRequestData;
    }

    
    /**
     * Prepares RevocationRequestData to check for not equals method.
     * @return RevocationRequestData
     */
    public RevocationRequestData getRevocationRequestForNotEqual() {

        final RevocationRequestData revocationRequestData = new RevocationRequestData();
        certificateAuthorityData= new CertificateAuthoritySetUpData().getCertificateAuthotityForNotEqual();
        entityInfoData =new EntitySetUpData().getEntityForNotEqual();
        certificateData =new CertificateSetUpData().getCertificateForEqual();
        certificateDatas.add(certificateData);
        revocationRequestData.setId(7);
        revocationRequestData.setCaEntity(certificateAuthorityData);
        revocationRequestData.setCertificatesToRevoke(certificateDatas);
        revocationRequestData.setCrlEntryExtensionsJSONData(crlEntryExtensionsJSONData);
        revocationRequestData.setEntity(entityInfoData);
        revocationRequestData.setStatus(RevocationRequestStatus.NEW);
       
        return revocationRequestData;
    }
}


