package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.resource;

import static org.junit.Assert.assertEquals;

import java.io.*;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.StreamingOutput;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.filter.CertificateBasicDetailsDTO;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.filter.CertificateResponseDTO;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.CertificateResourceHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util.FilterMapper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.validator.input.InputValidator;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.CertificateManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;

@RunWith(MockitoJUnitRunner.class)
public class CertificateResourceTest {

    @InjectMocks
    CertificateResource certificateResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(CertificateResource.class);

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    FilterMapper filterMapper;

    @Mock
    InputValidator filterValidation;

    @Mock
    CommonUtil commonUtil;

    @Mock
    StreamingOutput streamingOutput;

    @Mock
    CertificateManagementServiceLocal certificateManagementServiceLocal;

    @Mock
    CertificateResourceHelper certificateResourceHelper;

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    EntityCertificateManagementService entityCertificateManagementService;

    @Mock
    FileUtility fileUtility;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private final static int STATUS_OK = 200;

    Certificate entityCertificate;
    SetUPData setUPData;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    ObjectMapperUtilTest objectMapperUtilTest;

    private static CertificateResponseDTO certificateResponseDTO;
    private static CertificateSummaryDTO certSummaryDTO;
    public static final String FETCH_RESPONSE_IGNORED_FIELDS = "keySize";
    public static final String LOAD_RESPONSE_IGNORED_FIELDS = "id,notBefore";
    public static final String CERTIFICATE_SUMMARY_RESPONSE_IGNORED_FIELDS = "notBefore,keySize,type,signatureAlgorithm";

    /**
     * Method for setting up test data.
     */
    @Before
    public void setUp() throws Exception {

        certificateResponseDTO = new CertificateResponseDTO();
        certSummaryDTO = new CertificateSummaryDTO();

        objectMapperUtilTest = new ObjectMapperUtilTest();
        setUPData = new SetUPData();

        entityCertificate = setUPData.getCertificate("certificates/Entity.crt");

        certSummaryDTO.setName("caentity");
        certSummaryDTO.setType(EntityType.CA_ENTITY);
        Mockito.when(pkiManagerEServiceProxy.getEntityCertificateManagementService()).thenReturn(entityCertificateManagementService); 
        Mockito.when(pkiManagerEServiceProxy.getCaCertificateManagementService()).thenReturn(caCertificateManagementService); 

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(certificateResource);
        response = new MockHttpResponse();
    }

    private CertificateSummaryDTO getCertificateSummaryDTO() {
        final CertificateSummaryDTO certificateSummaryDTO = new CertificateSummaryDTO();
        certificateSummaryDTO.setName("entity");
        certificateSummaryDTO.setType(EntityType.ENTITY);
        return certificateSummaryDTO;
    }

    private CertificateBasicDetailsDTO getCertificateBasicDetailsDTO() {

        final CertificateBasicDetailsDTO certificateBasicDetailsDTO = new CertificateBasicDetailsDTO();
        certificateBasicDetailsDTO.setType(EntityType.CA_ENTITY);
        certificateBasicDetailsDTO.setStatus(CertificateStatus.ACTIVE);
        certificateBasicDetailsDTO.setId(1);

        certificateResponseDTO.setDetails(certificateBasicDetailsDTO);
        return certificateBasicDetailsDTO;
    }

    private CertificateDTO getCertificateDTO() {

        final CertificateDTO certificateDTO = new CertificateDTO();
        final FilterDTO filterDTO = getFilterDTO();
        certificateDTO.setFilter(filterDTO);
        return certificateDTO;
    }

    private FilterDTO getFilterDTO() {

        final FilterDTO filterDTO = new FilterDTO();
        filterDTO.setIssuer("MyRoot");

        CertificateStatus[] certStatus = new CertificateStatus[1];
        for (int i = 0; i < 1; i++) {
            certStatus[i] = CertificateStatus.ACTIVE;
        }
        filterDTO.setStatus(certStatus);

        EntityType[] entityTypes = new EntityType[1];
        for (int i = 0; i < 1; i++) {
            entityTypes[i] = EntityType.CA_ENTITY;
        }
        filterDTO.setType(entityTypes);
        return filterDTO;
    }

    @Test
    public void testCount() throws Exception {

        Mockito.when(filterValidation.validateFilterDTO(Mockito.any(FilterDTO.class))).thenReturn(true);

        final FilterDTO filterDTO = getFilterDTO();
        Mockito.when(certificateManagementServiceLocal.getCertificateCount(filterMapper.toCertificateFilter(filterDTO))).thenReturn(1l);

        request = MockHttpRequest.post("/certificatelist/count");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(filterDTO).getBytes("UTF-8"));

        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());

    }

    @Test
    public void testFetch() throws Exception {

        final CertificateDTO certificateDTO = getCertificateDTO();

        final Set<String> ignoreProperties = new HashSet<>(Arrays.asList("keySize"));

        Mockito.when(filterValidation.validate(Mockito.any(CertificateDTO.class))).thenReturn(true);

        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificate.setId(1);
        Mockito.when(certificateManagementServiceLocal.getCertificates(Mockito.any(CertificateFilter.class))).thenReturn(Arrays.asList(certificate));

        final CertificateBasicDetailsDTO certificateBasicDetailsDTO = getCertificateBasicDetailsDTO();
        Mockito.when(certificateResourceHelper.getCertificateBasicDetailsList(Mockito.any(Certificate.class))).thenReturn(certificateBasicDetailsDTO);

        Mockito.when(certificateResourceHelper.getIgnoredProperties(FETCH_RESPONSE_IGNORED_FIELDS)).thenReturn(ignoreProperties);

        Mockito.when(objectMapperUtil.getCertficateSerializerMapper(ignoreProperties)).thenReturn(objectMapperUtilTest.getCertficateSerializerMapper(ignoreProperties));

        request = MockHttpRequest.post("/certificatelist/fetch");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(certificateDTO).getBytes("UTF-8"));

        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());

    }

    @Test
    public void testLoad() throws Exception {

        final Set<String> ignoredProperties = new HashSet<>(Arrays.asList("id", "notBefore"));
        final Set<String> extensionsFilterProperties = new HashSet<String>();

        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificate.setId(1);
        Mockito.when(certificateManagementServiceLocal.getCertificates(Mockito.any(CertificateFilter.class))).thenReturn(Arrays.asList(certificate));

        Mockito.when(certificateResourceHelper.getCertificateResponse(Mockito.any(Certificate.class))).thenReturn(certificateResponseDTO);

        Mockito.when(certificateResourceHelper.getIgnoredProperties(LOAD_RESPONSE_IGNORED_FIELDS)).thenReturn(ignoredProperties);

        Mockito.when(objectMapperUtil.getCertficateSerializerMapper(ignoredProperties, extensionsFilterProperties)).thenReturn(
                objectMapperUtilTest.getCertficateSerializerMapper(ignoredProperties, extensionsFilterProperties));

        request = MockHttpRequest.get("/certificatelist/load/1");

        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());

    }

    @Test
    public void testSummary_CaEntity() throws Exception {

        final Set<String> ignoreProperties = new HashSet<>(Arrays.asList("keySize", "id", "notBefore", "type", "signatureAlgorithm"));

        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificate.setId(1);
        Mockito.when(caCertificateManagementService.listCertificates(certSummaryDTO.getName(), CertificateStatus.values())).thenReturn(Arrays.asList(certificate));

        final CertificateBasicDetailsDTO certificateBasicDetailsDTO = getCertificateBasicDetailsDTO();
        Mockito.when(certificateResourceHelper.getCertificateBasicDetailsList(Mockito.any(Certificate.class))).thenReturn(certificateBasicDetailsDTO);

        Mockito.when(certificateResourceHelper.getLatestCertificatesForSummary(Mockito.anyListOf(Certificate.class))).thenReturn(Arrays.asList(certificate));
        Mockito.when(certificateResourceHelper.getCertificateBasicDetailsList(Mockito.any(Certificate.class))).thenReturn(certificateBasicDetailsDTO);

        Mockito.when(certificateResourceHelper.getIgnoredProperties(CERTIFICATE_SUMMARY_RESPONSE_IGNORED_FIELDS)).thenReturn(ignoreProperties);

        Mockito.when(objectMapperUtil.getCertficateSerializerMapper(ignoreProperties)).thenReturn(objectMapperUtilTest.getCertficateSerializerMapper(ignoreProperties));

        request = MockHttpRequest.post("/certificatesummary/fetch");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(certSummaryDTO).getBytes("UTF-8"));

        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());

    }

    @Test
    public void testSummary_Entity() throws Exception {

        final Set<String> ignoreProperties = new HashSet<>(Arrays.asList("keySize", "id", "notBefore", "type", "signatureAlgorithm"));

        final CertificateSummaryDTO entityCertSummaryDTO = getCertificateSummaryDTO();
        Mockito.when(entityCertificateManagementService.listCertificates(entityCertSummaryDTO.getName(), CertificateStatus.values())).thenReturn(Arrays.asList(entityCertificate));

        final CertificateBasicDetailsDTO certificateBasicDetailsDTO = getCertificateBasicDetailsDTO();
        Mockito.when(certificateResourceHelper.getCertificateBasicDetailsList(Mockito.any(Certificate.class))).thenReturn(certificateBasicDetailsDTO);

        Mockito.when(certificateResourceHelper.getLatestCertificatesForSummary(Mockito.anyListOf(Certificate.class))).thenReturn(Arrays.asList(entityCertificate));
        Mockito.when(certificateResourceHelper.getCertificateBasicDetailsList(Mockito.any(Certificate.class))).thenReturn(certificateBasicDetailsDTO);

        Mockito.when(certificateResourceHelper.getIgnoredProperties(CERTIFICATE_SUMMARY_RESPONSE_IGNORED_FIELDS)).thenReturn(ignoreProperties);

        Mockito.when(objectMapperUtil.getCertficateSerializerMapper(ignoreProperties)).thenReturn(objectMapperUtilTest.getCertficateSerializerMapper(ignoreProperties));

        request = MockHttpRequest.post("/certificatesummary/fetch");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(entityCertSummaryDTO).getBytes("UTF-8"));

        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());

    }

    @Test
    public void testDownload() throws URISyntaxException, IOException, CertificateException {

        final DownloadDTO downloadDTO = setUPData.getDownloadDTO();

        request = MockHttpRequest.post("/certificate/download");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(downloadDTO).getBytes("UTF-8"));

        Mockito.doNothing().when(filterValidation).validateDownloadDTO(downloadDTO);

        final CertificateFilter certificateFilter = getCertificateFilter(downloadDTO);
        Mockito.when(filterMapper.toCertificateFilter(downloadDTO)).thenReturn(certificateFilter);

        final List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(setUPData.createSubCACertificate("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer"));
        certificates.add(setUPData.createRootCertificate("certificates/ARJ_Root-38c7880b5d1026b6-1450954693450.cer"));
        Mockito.when(certificateManagementServiceLocal.getCertificates(certificateFilter)).thenReturn(certificates);

        final File[] files = new File[certificates.size()];
        files[0] = new File("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.jks");
        files[1] = new File("certificates/ARJ_Root-38c7880b5d1026b6-1450954693450.jks");
        Mockito.when(certificateResourceHelper.createKeyStoreForCertificates(downloadDTO, certificates)).thenReturn(files);

        final File tarFile = new File("src/test/resources/certificates/certificates-1450954693463.tar.gz");
        Mockito.when(fileUtility.createArchiveFile(Mockito.any(File[].class), Mockito.anyString())).thenReturn(tarFile);

        Mockito.doNothing().when(fileUtility).deleteFiles(files);
        Mockito.when(commonUtil.getStreamingOutput(files[0])).thenReturn(streamingOutput);

        dispatcher.invoke(request, response);
        assertEquals(STATUS_OK, response.getStatus());

    }

    public CertificateFilter getCertificateFilter(final DownloadDTO downloadDTO) {

        final CertificateFilter certificateFilter = new CertificateFilter();
        certificateFilter.setOffset(0);
        certificateFilter.setLimit(downloadDTO.getCertificateIds().length);
        certificateFilter.setCertificateIdList(downloadDTO.getCertificateIds());
        return certificateFilter;

    }

    @Test
    public void testSummary_CaEntity_v1() throws Exception {
        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificate.setId(1);
        Mockito.when(caCertificateManagementService.listCertificates_v1(certSummaryDTO.getName(), CertificateStatus.values())).thenReturn(Arrays.asList(certificate));
        Mockito.when(certificateResourceHelper.getLatestCertificatesForSummary(Mockito.anyListOf(Certificate.class))).thenReturn(Arrays.asList(certificate));
        prepareData(certificate);
    }

    @Test
    public void testSummary_Entity_v1() throws Exception {
        final CertificateSummaryDTO entityCertSummaryDTO = getCertificateSummaryDTO();
        Mockito.when(entityCertificateManagementService.listCertificates_v1(entityCertSummaryDTO.getName(), CertificateStatus.values())).thenReturn(Arrays.asList(entityCertificate));
        Mockito.when(certificateResourceHelper.getLatestCertificatesForSummary(Mockito.anyListOf(Certificate.class))).thenReturn(Arrays.asList(entityCertificate));
        prepareData(entityCertificate);
    }

    private void prepareData(final Certificate certificate) throws URISyntaxException, UnsupportedEncodingException {
        final Set<String> ignoreProperties = new HashSet<>(Arrays.asList("keySize", "id", "notBefore", "type", "signatureAlgorithm"));

        final CertificateBasicDetailsDTO certificateBasicDetailsDTO = getCertificateBasicDetailsDTO();

        Mockito.when(certificateResourceHelper.getCertificateBasicDetailsList(Mockito.any(Certificate.class))).thenReturn(certificateBasicDetailsDTO);

        Mockito.when(certificateResourceHelper.getIgnoredProperties(CERTIFICATE_SUMMARY_RESPONSE_IGNORED_FIELDS)).thenReturn(ignoreProperties);

        Mockito.when(objectMapperUtil.getCertficateSerializerMapper(ignoreProperties)).thenReturn(objectMapperUtilTest.getCertficateSerializerMapper(ignoreProperties));

        request = MockHttpRequest.post("/certificatesummary/fetch");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(certSummaryDTO).getBytes("UTF-8"));

        dispatcher.invoke(request, response);
        assertEquals(STATUS_OK, response.getStatus());
    }
}
