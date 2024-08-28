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
 *---------------------------------------------------------------------------- */
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.entitymanagement.entitylist;

import static org.junit.Assert.*;

import java.io.*;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.core.MediaType;
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
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CSRBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.PKCS10CertificationRequestSetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityCertificateOperationsHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.validator.input.InputValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.adapter.EntitiesFilterAdapter;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.validators.DTOValidator;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.setup.CAEntitySetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.resourcesV1.entitymanagement.EntityListResource;
import com.ericsson.oss.itpf.security.pki.manager.rest.common.KeyStoreHelper;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.AttributeType;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.EntityManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.*;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link com.ericsson.oss.itpf.security.pki.manager.resourcesV1.entitymanagement.EntityListResource
 * 
 * @author tcspred
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class EntityListResourceTest {

    @InjectMocks
    com.ericsson.oss.itpf.security.pki.manager.resourcesV1.entitymanagement.EntityListResource entityListResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityListResource.class);

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    EntityManagementServiceLocal entityManagementServiceLocal;

    @Mock
    private DTOValidator dtoValidator;

    @Mock
    private EntitiesFilterAdapter entityFilterAdapter;

    @Mock
    CommonUtil commonUtil;

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
    EntityCertificateOperationsHelper entityCertificateOperationsHelper;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private PKCS10CertificationRequestSetUPData pKCS10CertificationRequestSetUPData;

    private final static int STATUS_OK = 200;
    private final static String ENTITY_DELETED = "Entity deleted Successfully.";

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
        Mockito.when(pkiManagerEServiceProxy.getEntityManagementService()).thenReturn(entityManagementService); 
        Mockito.when(pkiManagerEServiceProxy.getEntityCertificateManagementService()).thenReturn(entityCertificateManagementService); 


        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(entityListResource);
        response = new MockHttpResponse();

        module.addSerializer(EntityProfile.class, new AbstractProfileSerializer());
        module.addSerializer(X509Certificate.class, new X509CertificateSerializer());
        module.addSerializer(EntityInfo.class, new EntityInfoFetchSerializer());
        module.addSerializer(CertificateAuthority.class, new CertificateAuthorityFetchSerializer());

        mapper.registerModule(module);

        caEntitiesArray = new JSONArray(mapper.writeValueAsString(entities.getCAEntities()));
    }

    /**
     * Method to test rest service for deleting ca entity
     */

    @Test
    public void testEntityListDeleteCAEntity() throws URISyntaxException, UnsupportedEncodingException {
        request = MockHttpRequest.delete("/1.0/entitylist/delete/CA_ENTITY/1");
        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(ENTITY_DELETED, response.getContentAsString());
    }

    /**
     * Method to test rest service for deleting end entity
     */

    @Test
    public void testEntityListDeleteEntity() throws URISyntaxException, UnsupportedEncodingException {
        request = MockHttpRequest.delete("/1.0/entitylist/delete/ENTITY/1");
        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(ENTITY_DELETED, response.getContentAsString());
    }

    /**
     * Method to test rest service for getting count of entities that match with filter criteria
     */

    @Test
    public void testEntityListCount() throws URISyntaxException, UnsupportedEncodingException {
        final EntityFilterDTO filterDTO = getEntityFilterDTO();
        final EntitiesFilter entitiesFilter = getEntitiesFilter();

        Mockito.when(dtoValidator.validateEntityFilterDTO(filterDTO)).thenReturn(true);
        Mockito.when(entityFilterAdapter.toEntitiesFilterForCount(filterDTO)).thenReturn(entitiesFilter);
        Mockito.when(entityManagementServiceLocal.getEntitiesCountByFilter(entitiesFilter)).thenReturn(1);

        request = MockHttpRequest.post("/1.0/entitylist/count");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(filterDTO).getBytes("UTF-8"));

        dispatcher.invoke(request, response);

        assertEquals(String.valueOf(1), response.getContentAsString());
        assertEquals(response.getStatus(), STATUS_OK);
    }

    @Test
    public void testEntityListCountNotValid() throws URISyntaxException, UnsupportedEncodingException {
        final EntityFilterDTO filterDTO = getEntityFilterDTO();
        final EntitiesFilter entitiesFilter = getEntitiesFilter();

        Mockito.when(dtoValidator.validateEntityFilterDTO(filterDTO)).thenReturn(false);
        Mockito.when(entityFilterAdapter.toEntitiesFilterForCount(filterDTO)).thenReturn(entitiesFilter);
        Mockito.when(entityManagementServiceLocal.getEntitiesCountByFilter(entitiesFilter)).thenReturn(1);

        request = MockHttpRequest.post("/1.0/entitylist/count");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(filterDTO).getBytes("UTF-8"));

        dispatcher.invoke(request, response);
        assertEquals(response.getStatus(), STATUS_OK);
    }

    /**
     * Method to test rest service for fetching all the profiles
     */

    @Test
    public void testEntityListFetch() throws URISyntaxException, UnsupportedEncodingException {

        final EntityDTO entityDTO = getEntityDTO();
        final EntitiesFilter entitiesFilter = getEntitiesFilter();

        Mockito.when(dtoValidator.validateEntityDTO(entityDTO)).thenReturn(true);
        Mockito.when(entityFilterAdapter.toEntitiesFilterForFetch(entityDTO)).thenReturn(entitiesFilter);
        Mockito.when(commonUtil.mergeJsonArray(Mockito.any(JSONArray.class), Mockito.any(JSONArray.class))).thenReturn(caEntitiesArray);
        Mockito.when(commonUtil.placeAttributeAtFirstForEntities(caEntitiesArray, AttributeType.ID, "1")).thenReturn(caEntitiesArray.toString());
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITIES_FETCH_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.ENTITIES_FETCH_MAPPER));

        request = MockHttpRequest.post("/1.0/entitylist/fetch");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(entityDTO).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
    }

    @Test
    public void testEntityListNotValidCount() throws URISyntaxException, UnsupportedEncodingException {
        final EntityFilterDTO filterDTO = getEntityFilterDTO();
        final EntitiesFilter entitiesFilter = getEntitiesFilter();

        Mockito.when(dtoValidator.validateEntityFilterDTO(filterDTO)).thenReturn(false);
        Mockito.when(entityFilterAdapter.toEntitiesFilterForCount(filterDTO)).thenReturn(entitiesFilter);
        Mockito.when(entityManagementServiceLocal.getEntitiesCountByFilter(entitiesFilter)).thenReturn(1);

        request = MockHttpRequest.post("/entitylist/count");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(filterDTO).getBytes("UTF-8"));

        dispatcher.invoke(request, response);
        assertEquals(response.getStatus(), 404);
    }

    /**
     * Method to test rest service for issue Certificate with CSR UPLoad
     */
    @Test
    public void testIssueCertificate() throws Exception {

        final KeyStoreFileDTO keyStoreFileDTO = setUPData.getKeyStoreFileDTO();

        Mockito.doNothing().when(inputValidator).validateFileDTO(keyStoreFileDTO);

        final CertificateRequest certificateRequest = getCertificateRequest();
        Mockito.when(cSRBuilder.generateCSR(Mockito.anyString())).thenReturn(certificateRequest);

        final com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate entityCertificate = setUPData.getEntityCertificate("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer");
        Mockito.when(entityCertificateManagementService.generateCertificate(keyStoreFileDTO.getName(), certificateRequest)).thenReturn(entityCertificate);

        final List<com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate> certificates = setUPData
                .getEntityCertificateChain("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer");
        Mockito.when(entityCertificateOperationsHelper.getEntityCertificateChain(keyStoreFileDTO.getName(), keyStoreFileDTO.isChain(), entityCertificate)).thenReturn(certificates);

        final KeyStoreInfo keyStoreInfo = getKeyStroeInfo(keyStoreFileDTO);
        Mockito.when(keyStoreHelper.createKeyStoreInfo(keyStoreFileDTO.getName(), keyStoreFileDTO.getFormat(), keyStoreFileDTO.getPassword(), keyStoreFileDTO.getName())).thenReturn(keyStoreInfo);

        Mockito.when(keyStoreHelper.createKeyStore(keyStoreInfo, certificates)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        final String filename = Constants.TMP_DIR + Constants.FILE_SEPARATOR + "ARJ_Root-35c35df3596fc0e6-1450954693459.jks";
        final File file = new File(filename);
        file.createNewFile();

        request = MockHttpRequest.post("/1.0/entitylist/issue/csrupload");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(keyStoreFileDTO).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());
        assertNotNull(response.getContentAsString());
        file.delete();
    }

    /**
     * Method to test rest service for issue CACertificate
     */
    @Test
    public void testIssueCACert() throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, OperatorCreationException, CertificateException,
            URISyntaxException, Exception {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithOutChain();
        request = MockHttpRequest.post("/1.0/entitylist/issue");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(certificateRequestDTO).getBytes("UTF-8"));

        Mockito.when(entityCertificateOperationsHelper.issueCertificateForCA(certificateRequestDTO)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        final String filename = Constants.TMP_DIR + Constants.FILE_SEPARATOR + "ARJ_Root-35c35df3596fc0e6-1450954693459.jks";
        final File file = new File(filename);
        file.createNewFile();

        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());
        assertNotNull(response.getContentAsString());
    }

    /**
     * Method to test rest service for issue EndEntity Certificate
     */
    @Test
    public void testIssueEndEntityCert() throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, OperatorCreationException,
            CertificateException, URISyntaxException, Exception {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getEndEntityCertificateRequestDTOWithOutChain();
        request = MockHttpRequest.post("/1.0/entitylist/issue");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(certificateRequestDTO).getBytes("UTF-8"));

        Mockito.when(entityCertificateOperationsHelper.issueCertificateForEntity(certificateRequestDTO)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        final String filename = Constants.TMP_DIR + Constants.FILE_SEPARATOR + "ARJ_Root-35c35df3596fc0e6-1450954693459.jks";
        final File file = new File(filename);
        file.createNewFile();

        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());
        assertNotNull(response.getContentAsString());
    }

    /**
     * Method to test rest service for Re-issue CACertificate
     */
    @Test
    public void testReIssueCACert() throws Exception {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithOutChain();
        request = MockHttpRequest.post("/1.0/entitylist/reissue");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(certificateRequestDTO).getBytes("UTF-8"));

        try {
            dispatcher.invoke(request, response);
        } catch (Exception exception) {
            assertTrue(exception.getMessage().contains("renew for CA_ENTITY is not supported."));
        }
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

    private EntityDTO getEntityDTO() {
        final EntityDTO entityDTO = new EntityDTO();

        entityDTO.setId(1);
        entityDTO.setOffset(0);
        entityDTO.setLimit(10);
        entityDTO.setFilter(getEntityFilterDTO());

        return entityDTO;
    }

    private EntityFilterDTO getEntityFilterDTO() {
        final EntityFilterDTO entityFilterDTO = new EntityFilterDTO();
        final List<EntityStatus> status = new ArrayList<EntityStatus>();
        final List<EntityType> entityTypes = new ArrayList<EntityType>();

        entityTypes.add(EntityType.CA_ENTITY);
        status.add(EntityStatus.ACTIVE);
        entityFilterDTO.setCertificateAssigned(0);
        entityFilterDTO.setName("rest%");
        entityFilterDTO.setStatus(status);
        entityFilterDTO.setType(entityTypes);

        return entityFilterDTO;
    }

    private EntitiesFilter getEntitiesFilter() {
        final EntitiesFilter entitiesFilter = new EntitiesFilter();

        entitiesFilter.setCertificateAssigned(0);
        entitiesFilter.setId(1);
        entitiesFilter.setLimit(10);
        entitiesFilter.setName("rest%");
        entitiesFilter.setOffset(0);

        final List<EntityType> entityTypes = new ArrayList<EntityType>();

        entityTypes.add(EntityType.CA_ENTITY);
        entitiesFilter.setStatus(getStatusFilter());
        entitiesFilter.setType(entityTypes);

        return entitiesFilter;
    }

    private List<EntityStatus> getStatusFilter() {
        final List<EntityStatus> status = new ArrayList<EntityStatus>();
        status.add(EntityStatus.ACTIVE);
        return status;
    }
}