/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.rest.helpers;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.Response.Status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.RevocationService;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.rest.mappers.CertificateRevocationInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.LoadErrorProperties;

@RunWith(MockitoJUnitRunner.class)
public class RevocationRestResourceHelperTest {

    @InjectMocks
    RevocationRestResourceHelper revocationRestResourceHelper;

    @Mock
    RevocationService revocationService;

    @Mock
    CertificateRevocationInfoMapper certificateRevokeInfoMapper;

    @Mock
    private LoadErrorProperties loadErrorProperties;

    @Mock
    PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Mock
    private Logger logger;
    private String caEntityName;
    private String caCerficateSerialNumber;
    private String issuerDN_CA;
    private String subjectDN_CA;

    private static final String CERTIFICATE_NOT_FOUND = "Certificate not found";
    private static final String NO_VALID_CERTIFICATE = "No valid Certificate found";
    private static final String REVOCATION_STATUS_MESSAGE_FOR_ENTITY = "All the Entity Certificates in a state compatible with the revocation have been revoked.";

    private EntityRevocationInfoDTO entityRevocationInfoDTO;
    private RevocationStatusDTO revocationStatusDto;
    private CertificateRevocationInfoDTO certificateRevokeDTO;
    private DNBasedCertificateIdentifier dnBasedCertificateIdentifier;
    private List<RevocationStatusDTO> revokeStatusDTOList = new ArrayList<RevocationStatusDTO>();
    private List<CertificateRevocationInfoDTO> certificateRevocationInfoDTOs = new ArrayList<CertificateRevocationInfoDTO>();

    @Before
    public void setUp() throws Exception {

        caEntityName = "ENM_SubCA14";
        caCerficateSerialNumber = "5846e6e7c5d3c7a2";
        issuerDN_CA = "CN=ARJ_Root";
        subjectDN_CA = "CN=ARJ_Sub14";

        entityRevocationInfoDTO = new EntityRevocationInfoDTO();

        entityRevocationInfoDTO.setEntityName(caEntityName);
        entityRevocationInfoDTO.setRevocationReason(RevocationReason.KEY_COMPROMISE);
        revocationStatusDto = new RevocationStatusDTO();

        dnBasedCertificateIdentifier = new DNBasedCertificateIdentifier();
        dnBasedCertificateIdentifier.setCerficateSerialNumber(caCerficateSerialNumber);
        dnBasedCertificateIdentifier.setIssuerDN(issuerDN_CA);
        dnBasedCertificateIdentifier.setSubjectDN(subjectDN_CA);
        Mockito.when(pkiManagerEServiceProxy.getRevocationService()).thenReturn(revocationService); 

    }

    @Test
    public void testGetRevokeStatusDTOList_With_CAEntity_Revocation_Info_Success() {
        revocationStatusDto.setStatus(Status.OK.getStatusCode());
        revocationStatusDto.setMessage(REVOCATION_STATUS_MESSAGE_FOR_ENTITY);
        revokeStatusDTOList.add(revocationStatusDto);

        Mockito.doNothing().when(revocationService).revokeCAEntityCertificates(entityRevocationInfoDTO.getEntityName(), entityRevocationInfoDTO.getRevocationReason(), null);
        final List<RevocationStatusDTO> actualRevokeStatusDTOList = revocationRestResourceHelper.getRevokeStatusDTOList(entityRevocationInfoDTO, EntityType.CA_ENTITY);
        assertNotNull(actualRevokeStatusDTOList);
        assertEquals(revokeStatusDTOList, actualRevokeStatusDTOList);
        assertTrue(revokeStatusDTOList.get(0).getMessage().contains(REVOCATION_STATUS_MESSAGE_FOR_ENTITY));

    }

    @Test
    public void testGetRevokeStatusDTOList_With_CAEntity_Revocation_Info_Failure() {
        revocationStatusDto.setStatus(Status.BAD_REQUEST.getStatusCode());
        revocationStatusDto.setMessage(CERTIFICATE_NOT_FOUND);
        revokeStatusDTOList.add(revocationStatusDto);

        Mockito.doThrow(new CertificateNotFoundException(CERTIFICATE_NOT_FOUND)).when(revocationService)
                .revokeCAEntityCertificates(entityRevocationInfoDTO.getEntityName(), entityRevocationInfoDTO.getRevocationReason(), null);

        final List<RevocationStatusDTO> actualRevokeStatusDTOList = revocationRestResourceHelper.getRevokeStatusDTOList(entityRevocationInfoDTO, EntityType.CA_ENTITY);

        assertNotNull(actualRevokeStatusDTOList);
        assertEquals(revokeStatusDTOList, actualRevokeStatusDTOList);
        assertTrue(revokeStatusDTOList.get(0).getMessage().contains(CERTIFICATE_NOT_FOUND));
    }

    @Test
    public void testGetRevokeStatusDTOList_With_Entity_Revocation_Info() {
        revocationStatusDto.setStatus(Status.OK.getStatusCode());
        revocationStatusDto.setMessage(REVOCATION_STATUS_MESSAGE_FOR_ENTITY);
        revokeStatusDTOList.add(revocationStatusDto);

        Mockito.doNothing().when(revocationService).revokeEntityCertificates(entityRevocationInfoDTO.getEntityName(), entityRevocationInfoDTO.getRevocationReason(), null);
        final List<RevocationStatusDTO> actualRevokeStatusDTOList = revocationRestResourceHelper.getRevokeStatusDTOList(entityRevocationInfoDTO, EntityType.ENTITY);
        assertNotNull(actualRevokeStatusDTOList);
        assertEquals(revokeStatusDTOList, actualRevokeStatusDTOList);
        assertTrue(revokeStatusDTOList.get(0).getMessage().contains(REVOCATION_STATUS_MESSAGE_FOR_ENTITY));
    }

    @Test
    public void testGetRevokeStatusDTOList_With_Certificate_Revocation_Info_Success() {
        final String message = "Certificate has been revoked.";
        revocationStatusDto.setStatus(Status.OK.getStatusCode());
        revocationStatusDto.setMessage(message);
        revocationStatusDto.setCode("30002");
        revokeStatusDTOList.add(revocationStatusDto);
        certificateRevocationInfoDTOs.add(getCertificateRevokeDTO());

        Mockito.when(certificateRevokeInfoMapper.getDnBasedCertificateIdentifier((CertificateRevocationInfoDTO) Mockito.anyObject())).thenReturn(dnBasedCertificateIdentifier);
        Mockito.when(loadErrorProperties.getRevocationErrorCode(message)).thenReturn("30002");
        Mockito.doNothing().when(revocationService).revokeCertificateByDN(dnBasedCertificateIdentifier, getCertificateRevokeDTO().getRevocationReason(), null);
        Mockito.when(certificateRevokeInfoMapper.getRevocationStatusDTO(getCertificateRevokeDTO(), message, Status.OK.getStatusCode(), "30002")).thenReturn(revocationStatusDto);
        final List<RevocationStatusDTO> actualRevokeStatusDTOList = revocationRestResourceHelper.getRevokeStatusDTOList(certificateRevocationInfoDTOs, EntityType.CA_ENTITY);
        assertNotNull(actualRevokeStatusDTOList);
        assertEquals(revokeStatusDTOList, actualRevokeStatusDTOList);
    }

    @Test
    public void testGetRevokeStatusDTOList_With_CA_Certificate_Revocation_Info_Failure() {
        revocationStatusDto.setStatus(Status.BAD_REQUEST.getStatusCode());
        revocationStatusDto.setMessage(NO_VALID_CERTIFICATE);
        revocationStatusDto.setCode("30004");
        revokeStatusDTOList.add(revocationStatusDto);
        certificateRevocationInfoDTOs.add(getCertificateRevokeDTO());

        Mockito.when(loadErrorProperties.getRevocationErrorCode(NO_VALID_CERTIFICATE)).thenReturn("30004");
        Mockito.doThrow(new CertificateNotFoundException(NO_VALID_CERTIFICATE)).when(revocationService).revokeCertificateByDN(null, getCertificateRevokeDTO().getRevocationReason(), null);
        Mockito.when(certificateRevokeInfoMapper.getRevocationStatusDTO(getCertificateRevokeDTO(), NO_VALID_CERTIFICATE, Status.BAD_REQUEST.getStatusCode(), "30004")).thenReturn(revocationStatusDto);
        final List<RevocationStatusDTO> actualRevokeStatusDTOList = revocationRestResourceHelper.getRevokeStatusDTOList(certificateRevocationInfoDTOs, EntityType.CA_ENTITY);
        assertNotNull(actualRevokeStatusDTOList);
        assertEquals(revokeStatusDTOList.get(0), actualRevokeStatusDTOList.get(0));
    }

    @Test
    public void testGetRevokeStatusDTOList_With_Entity_Certificate_Revocation_Info_Failure() {
        String message = "Certificate has been revoked.";
        revocationStatusDto.setStatus(Status.OK.getStatusCode());
        revocationStatusDto.setMessage(message);
        revocationStatusDto.setCode("30002");
        revokeStatusDTOList.add(revocationStatusDto);
        certificateRevocationInfoDTOs.add(getCertificateRevokeDTO());

        Mockito.doNothing().when(revocationService).revokeCertificateByDN(dnBasedCertificateIdentifier, getCertificateRevokeDTO().getRevocationReason(), null);
        Mockito.when(loadErrorProperties.getRevocationErrorCode(message)).thenReturn("30002");
        Mockito.when(certificateRevokeInfoMapper.getRevocationStatusDTO(getCertificateRevokeDTO(), message, Status.OK.getStatusCode(), "30002")).thenReturn(revocationStatusDto);
        final List<RevocationStatusDTO> actualRevokeStatusDTOList = revocationRestResourceHelper.getRevokeStatusDTOList(certificateRevocationInfoDTOs, EntityType.ENTITY);
        assertNotNull(actualRevokeStatusDTOList);
        assertEquals(revokeStatusDTOList, actualRevokeStatusDTOList);
    }

    private CertificateRevocationInfoDTO getCertificateRevokeDTO() {
        certificateRevokeDTO = new CertificateRevocationInfoDTO();
        certificateRevokeDTO.setSerialNumber(caCerficateSerialNumber);
        certificateRevokeDTO.setIssuer(issuerDN_CA);
        certificateRevokeDTO.setSubject(subjectDN_CA);
        certificateRevokeDTO.setRevocationReason(RevocationReason.UNSPECIFIED);
        return certificateRevokeDTO;
    }
}
