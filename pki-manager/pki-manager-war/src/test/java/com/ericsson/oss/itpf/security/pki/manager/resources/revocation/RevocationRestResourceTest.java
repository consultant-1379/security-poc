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
package com.ericsson.oss.itpf.security.pki.manager.resources.revocation;

import java.io.IOException;
import java.util.*;

import javax.inject.Inject;
import javax.ws.rs.core.Response;

import org.json.JSONException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.CertificateRevocationInfoDTO;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.EntityRevocationInfoDTO;
import com.ericsson.oss.itpf.security.pki.manager.rest.helpers.RevocationRestResourceHelper;
import com.ericsson.oss.itpf.security.pki.manager.rest.mappers.CertificateRevocationInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

@RunWith(MockitoJUnitRunner.class)
public class RevocationRestResourceTest {

    @InjectMocks
    RevocationRestResource revocationRestResource;

    @Mock
    private Logger logger;

    @Mock
    CertificateRevocationInfoMapper certificateRevokeInfoMapper;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    ObjectMapper mapper;

    @Mock
    ObjectMapper commonMapper;

    @Mock
    RevocationRestResourceHelper revocationRestResourceHelper;

    @Mock
    CommonUtil commonUtil;

    ObjectMapperUtilTest objectMapperUtilTest;

    final String revocationInfoJsonString = "{\"entityName\":\"TestCA\",\"revocationReason\":\"AA_COMPROMISE\"}";

    final String certificatesRevocationInfoJsonString = "[{\"serialNumber\":\"346b8fb241e5e93f\",\"issuer\":\"CN=ARJ_Root\",\"subject\":\"CN=ARJ_Root\",\"revocationReason\":\"7\"}]";

    private Response response;
    private final int INTERNAL_ERROR = 500;

    @Test
    public void testRevokeCAEntity() throws IOException {
        Mockito.when(commonUtil.getRevocationInfoDTO(EntityRevocationInfoDTO.class, revocationInfoJsonString)).thenReturn(new EntityRevocationInfoDTO());
        revocationRestResource.revokeCAEntity(revocationInfoJsonString);
    }

    @Test
    public void testRevokeCAEntity_IOException() throws IOException {
        Mockito.when(commonUtil.getRevocationInfoDTO(EntityRevocationInfoDTO.class, "")).thenThrow(IOException.class);
        response = revocationRestResource.revokeCAEntity("");
        Assert.assertEquals(INTERNAL_ERROR, response.getStatus());
    }

    @Test
    public void testRevokeCAEntity_EmptyRevocationInfoDTO() throws IOException {
        Mockito.when(commonUtil.getRevocationInfoDTO(EntityRevocationInfoDTO.class, "")).thenReturn(new EntityRevocationInfoDTO());
        response = revocationRestResource.revokeCAEntity("");
        Assert.assertEquals(INTERNAL_ERROR, response.getStatus());
    }

    @Test
    public void testRevokeEntity() throws IOException {
        Mockito.when(commonUtil.getRevocationInfoDTO(EntityRevocationInfoDTO.class, revocationInfoJsonString)).thenReturn(new EntityRevocationInfoDTO());
        revocationRestResource.revokeEntity(revocationInfoJsonString);
    }

    @Test
    public void testRevokeEntity_EmptyRevocationInfoDTO() throws IOException {
        Mockito.when(commonUtil.getRevocationInfoDTO(EntityRevocationInfoDTO.class, "")).thenReturn(new EntityRevocationInfoDTO());
        response = revocationRestResource.revokeEntity("");
        Assert.assertEquals(INTERNAL_ERROR, response.getStatus());
    }

    @Test
    public void testRevokeEntity_IOException() throws IOException {
        Mockito.when(commonUtil.getRevocationInfoDTO(EntityRevocationInfoDTO.class, "")).thenThrow(IOException.class);
        response = revocationRestResource.revokeEntity("");
        Assert.assertEquals(INTERNAL_ERROR, response.getStatus());
    }

    @Test
    public void testRevokeCAEntityCertificates() throws JSONException, IOException {
        Mockito.when(commonUtil.getRevocationInfoDTOList(CertificateRevocationInfoDTO.class, certificatesRevocationInfoJsonString)).thenReturn(Arrays.asList(new CertificateRevocationInfoDTO()));
        revocationRestResource.revokeCAEntityCertificates(certificatesRevocationInfoJsonString);
    }

    @Test
    public void testRevokeCAEntityCertificates_EmptyCertificateRevocationInfoDTOList() throws JSONException, IOException {
        final List<CertificateRevocationInfoDTO> certificateRevocationInfoDTOList = new ArrayList<CertificateRevocationInfoDTO>();
        Mockito.when(commonUtil.getRevocationInfoDTOList(CertificateRevocationInfoDTO.class, "")).thenReturn(certificateRevocationInfoDTOList);
        response = revocationRestResource.revokeCAEntityCertificates("");
        Assert.assertEquals(INTERNAL_ERROR, response.getStatus());
    }

    @Test
    public void testRevokeCAEntityCertificates_JSONException() throws JSONException, IOException {
        Mockito.when(commonUtil.getRevocationInfoDTOList(CertificateRevocationInfoDTO.class, certificatesRevocationInfoJsonString)).thenThrow(JSONException.class);
        response = revocationRestResource.revokeCAEntityCertificates(certificatesRevocationInfoJsonString);
        Assert.assertEquals(INTERNAL_ERROR, response.getStatus());
    }

    @Test
    public void testrevokeEntityCertificates() throws JSONException, IOException {
        Mockito.when(commonUtil.getRevocationInfoDTOList(CertificateRevocationInfoDTO.class, certificatesRevocationInfoJsonString)).thenReturn(Arrays.asList(new CertificateRevocationInfoDTO()));
        revocationRestResource.revokeEntityCertificates(certificatesRevocationInfoJsonString);
    }

    @Test
    public void testRevokeEntityCertificates_EmptyCertificateRevocationInfoDTOList() throws JSONException, IOException {
        final List<CertificateRevocationInfoDTO> certificateRevocationInfoDTOList = new ArrayList<CertificateRevocationInfoDTO>();
        Mockito.when(commonUtil.getRevocationInfoDTOList(CertificateRevocationInfoDTO.class, "")).thenReturn(certificateRevocationInfoDTOList);
        response = revocationRestResource.revokeEntityCertificates("");
        Assert.assertEquals(INTERNAL_ERROR, response.getStatus());
    }

    @Test
    public void testRevokeEntityCertificates_JSONException() throws JSONException, IOException {
        Mockito.when(commonUtil.getRevocationInfoDTOList(CertificateRevocationInfoDTO.class, certificatesRevocationInfoJsonString)).thenThrow(JSONException.class);
        response = revocationRestResource.revokeEntityCertificates(certificatesRevocationInfoJsonString);
        Assert.assertEquals(INTERNAL_ERROR, response.getStatus());
    }
}
