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
package com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.entitylist;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.*;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.StreamingOutput;
import javax.xml.datatype.DatatypeConfigurationException;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.json.JSONArray;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CSRBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.PKCS10CertificationRequestSetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityCertificateOperationsHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.validator.input.InputValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.RevocationService;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.adapter.EntitiesFilterAdapter;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.validators.DTOValidator;
import com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.EntitiesResource;
import com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.setup.CAEntitySetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.common.KeyStoreHelper;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.EntityManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.*;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

@RunWith(MockitoJUnitRunner.class)
public class EntitiesResourceTest {

    @InjectMocks
    com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.EntitiesResource entitiesResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(EntitiesResource.class);

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    EntityManagementServiceLocal entityManagementServiceLocal;

    @Mock
    DTOValidator dtoValidator;

    @Mock
    EntitiesFilterAdapter entityFilterAdapter;

    @Mock
    CommonUtil commonUtil;

    @Mock
    StreamingOutput streamingOutput;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    ObjectMapperUtilTest testObjectMapperUtilTest;

    @Mock
    InputValidator inputValidator;

    @Mock
    CSRBuilder cSRBuilder;

    @Mock
    KeyStoreHelper keyStoreHelper;

    @Mock
    EntityCertificateManagementService entityCertificateManagementService;

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    EntityCertificateOperationsHelper entityCertificateOperationsHelper;

    @Mock
    RevocationService revocationService;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private PKCS10CertificationRequestSetUPData pKCS10CertificationRequestSetUPData;

    private final static int STATUS_OK = 200;

    CAEntity caEntity;
    List<CAEntity> caEntities = new ArrayList<CAEntity>();
    Entities entities = new Entities();

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;
    JSONArray caEntitiesArray;
    ObjectMapperUtilTest testObjectMapperUtil;

    private SetUPData setUPData;

    /**
     * Method for setting up test data.
     */

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @Before
    public void setup() throws DatatypeConfigurationException, IOException {

        pKCS10CertificationRequestSetUPData = new PKCS10CertificationRequestSetUPData();
        setUPData = new SetUPData();
        final CAEntitySetUpToTest caEntitySetUpToTest = new CAEntitySetUpToTest();
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        testObjectMapperUtil = new ObjectMapperUtilTest();
        caEntity = caEntitySetUpToTest.getCAEntity();
        caEntities.add(caEntity);
        entities.setCAEntities(caEntities);

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(entitiesResource);
        response = new MockHttpResponse();

        module.addSerializer(EntityProfile.class, new AbstractProfileSerializer());
        module.addSerializer(X509Certificate.class, new X509CertificateSerializer());
        module.addSerializer(EntityInfo.class, new EntityInfoFetchSerializer());
        module.addSerializer(CertificateAuthority.class, new CertificateAuthorityFetchSerializer());

        mapper.registerModule(module);

        caEntitiesArray = new JSONArray(mapper.writeValueAsString(entities.getCAEntities()));

        Mockito.when(pkiManagerEServiceProxy.getCaCertificateManagementService()).thenReturn(caCertificateManagementService);
        Mockito.when(pkiManagerEServiceProxy.getRevocationService()).thenReturn(revocationService);
        Mockito.when(pkiManagerEServiceProxy.getEntityCertificateManagementService()).thenReturn(entityCertificateManagementService);

    }

    /**
     * Method to test rest service for Re-issue CA Certificate with/without revocation
     * 
     * @throws URISyntaxException
     * @throws UnsupportedEncodingException
     */
    @Test
    public void testReIssueCACertificate() throws URISyntaxException, UnsupportedEncodingException {
        final CAReissueDTO caReissueDTO = setUPData.getCAReissueDTO();
        request = MockHttpRequest.post("/entities/caentity/reissue");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(caReissueDTO).getBytes("UTF-8"));

        Mockito.doNothing().when(inputValidator).validateCAReissueDTO(caReissueDTO);
        final ObjectMapper objectMapper = setUPData.getObjectMapper(ObjectMapperType.CAENTITY_REISSUE_MAPPER);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.CAENTITY_REISSUE_MAPPER)).thenReturn(objectMapper);

        caCertificateManagementService.renewCertificate(caReissueDTO.getName(), caReissueDTO.getReIssueType());
        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());
        assertNotNull(response.getContentAsString());
    }

    /**
     * Method to test rest service for Re-issue Certificate with CSR UPLoad
     */
    @Test
    public void testReIssueCertificate() throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, OperatorCreationException,
            CertificateException, URISyntaxException {

        final KeyStoreFileDTO keyStoreFileDTO = setUPData.getKeyStoreFileDTO();
        request = MockHttpRequest.post("/entities/reissue/csrupload");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(keyStoreFileDTO).getBytes("UTF-8"));

        Mockito.doNothing().when(inputValidator).validateFileDTO(keyStoreFileDTO);
        final ObjectMapper objectMapper = setUPData.getObjectMapper(ObjectMapperType.REISSUE_WITH_CSR_MAPPER);

        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.REISSUE_WITH_CSR_MAPPER)).thenReturn(objectMapper);
        final CertificateRequest certificateRequest = getCertificateRequest();
        Mockito.when(cSRBuilder.generateCSR(Mockito.anyString())).thenReturn(certificateRequest);

        final com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate entityCertificate = setUPData.getEntityCertificate("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer");
        Mockito.when(entityCertificateManagementService.renewCertificate(keyStoreFileDTO.getName(), certificateRequest)).thenReturn(entityCertificate);

        final List<com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate> certificates = setUPData
                .getEntityCertificateChain("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer");
        Mockito.when(entityCertificateOperationsHelper.getEntityCertificateChain(keyStoreFileDTO.getName(), keyStoreFileDTO.isChain(), entityCertificate)).thenReturn(certificates);

        final KeyStoreInfo keyStoreInfo = getKeyStroeInfo(keyStoreFileDTO);
        Mockito.when(keyStoreHelper.createKeyStoreInfo(keyStoreFileDTO.getName(), keyStoreFileDTO.getFormat(), keyStoreFileDTO.getPassword(), keyStoreFileDTO.getName())).thenReturn(keyStoreInfo);

        Mockito.when(keyStoreHelper.createKeyStore(keyStoreInfo, certificates)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        final String filename = Constants.TMP_DIR + Constants.FILE_SEPARATOR + "ARJ_Root-35c35df3596fc0e6-1450954693459.jks";
        final File file = new File(filename);
        file.createNewFile();
        Mockito.when(commonUtil.getStreamingOutput(file)).thenReturn(streamingOutput);

        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());
        assertNotNull(response.getContentAsString());

    }

    /**
     * Method to test rest service for Re-issue EndEntity Certificate
     */
    @Test
    public void testReIssueEndEntityCert() throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, OperatorCreationException,
            CertificateException, URISyntaxException, Exception {

        final EntityReissueDTO entityReissueDTO = setUPData.getEntityReissueDTO();
        request = MockHttpRequest.post("/entities/entity/reissue");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(entityReissueDTO).getBytes("UTF-8"));

        Mockito.when(entityCertificateOperationsHelper.rekeyEndEntityCertificate(entityReissueDTO)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");
        final ObjectMapper objectMapper = setUPData.getObjectMapper(ObjectMapperType.ENTITY_REISSUE_MAPPER);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_REISSUE_MAPPER)).thenReturn(objectMapper);

        final String filename = Constants.TMP_DIR + Constants.FILE_SEPARATOR + "ARJ_Root-35c35df3596fc0e6-1450954693459.jks";
        final File file = new File(filename);
        file.createNewFile();
        Mockito.when(commonUtil.getStreamingOutput(file)).thenReturn(streamingOutput);

        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());
        assertNotNull(response.getContentAsString());
    }

    private CertificateRequest getCertificateRequest() throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException, NoSuchProviderException, OperatorCreationException {

        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUPData.generatePKCS10Requestwithattributes();
        final CertificateRequest certificateRequest = new CertificateRequest();
        final PKCS10CertificationRequestHolder certificateRequestHolder = new PKCS10CertificationRequestHolder(pKCS10CertificationRequest);
        certificateRequest.setCertificateRequestHolder(certificateRequestHolder);
        return certificateRequest;
    }

    private KeyStoreInfo getKeyStroeInfo(final KeyStoreFileDTO keyStoreFileDTO) {

        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAliasName(keyStoreFileDTO.getName());
        keyStoreInfo.setFilePath("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.jks");
        keyStoreInfo.setKeyStoreType(keyStoreFileDTO.getFormat());
        keyStoreInfo.setPassword(keyStoreFileDTO.getPassword());
        return keyStoreInfo;
    }
}
