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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.*;
import java.text.ParseException;
import java.util.*;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.common.setupdata.EntitySetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.setupdata.KeyGenerationAlgorithmSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;

@RunWith(MockitoJUnitRunner.class)
public class CommandHandlerUtilsTest {
    @Spy
    Logger logger = LoggerFactory.getLogger(AlgorithmUtils.class);

    @InjectMocks
    private CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetProfileType() {
        ProfileType profileType = commandHandlerUtils.getProfileType(Constants.CERTIFICATE);
        assertEquals(ProfileType.CERTIFICATE_PROFILE, profileType);
        profileType = commandHandlerUtils.getProfileType(Constants.TRUST);
        assertEquals(ProfileType.TRUST_PROFILE, profileType);
        profileType = commandHandlerUtils.getProfileType(Constants.ENTITY);
        assertEquals(ProfileType.ENTITY_PROFILE, profileType);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetProfileTypeException() {
        commandHandlerUtils.getProfileType(Constants.EMPTY_STRING);
    }

    @Test
    public void testGetEntityType() {
        EntityType entityType = commandHandlerUtils.getEntityType(Constants.CA);
        assertEquals(EntityType.CA_ENTITY, entityType);
        entityType = commandHandlerUtils.getEntityType(Constants.EE);
        assertEquals(EntityType.ENTITY, entityType);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetEntityTypeException() {
        commandHandlerUtils.getEntityType(Constants.EMPTY_STRING);
    }

    @Test
    public void testGetProfileInstance() {
        final CertificateProfile certificateProfile = (CertificateProfile) commandHandlerUtils.getProfileInstance(ProfileType.CERTIFICATE_PROFILE);
        assertEquals(certificateProfile.getType(), ProfileType.CERTIFICATE_PROFILE);
        final TrustProfile trustProfile = (TrustProfile) commandHandlerUtils.getProfileInstance(ProfileType.TRUST_PROFILE);
        assertEquals(trustProfile.getType(), ProfileType.TRUST_PROFILE);

        final EntityProfile entityProfile = (EntityProfile) commandHandlerUtils.getProfileInstance(ProfileType.ENTITY_PROFILE);
        assertEquals(entityProfile.getType(), ProfileType.ENTITY_PROFILE);
    }

    @Test
    public void testGetEntityInstance() {
        final CAEntity caEntity = (CAEntity) commandHandlerUtils.getEntityInstance(EntityType.CA_ENTITY, "rootca");
        assertEquals(caEntity.getType(), EntityType.CA_ENTITY);
        final Entity entity = (Entity) commandHandlerUtils.getEntityInstance(EntityType.ENTITY, "entity");
        assertEquals(entity.getType(), EntityType.ENTITY);
    }

    @Test
    public void testSetProfiles() {
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setId(1);
        certificateProfile.setName("rootcertprofile");
        final TrustProfile trustProfile = new TrustProfile();
        trustProfile.setId(1);
        trustProfile.setName("roottrustprofile");
        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setId(1);
        entityProfile.setName("rootentityprofile");
        final List<CertificateProfile> listOfCertProfiles = new ArrayList<CertificateProfile>();
        listOfCertProfiles.add(certificateProfile);
        final List<TrustProfile> listOfTrustProfiles = new ArrayList<TrustProfile>();
        listOfTrustProfiles.add(trustProfile);
        final List<EntityProfile> listOfEntityProfiles = new ArrayList<EntityProfile>();
        listOfEntityProfiles.add(entityProfile);
        Profiles profiles = commandHandlerUtils.setProfiles(ProfileType.CERTIFICATE_PROFILE, listOfCertProfiles);
        assertEquals(profiles.getCertificateProfiles().size(), 1);
        profiles = commandHandlerUtils.setProfiles(ProfileType.ENTITY_PROFILE, listOfEntityProfiles);
        assertEquals(profiles.getEntityProfiles().size(), 1);
        profiles = commandHandlerUtils.setProfiles(ProfileType.TRUST_PROFILE, listOfTrustProfiles);
        assertEquals(profiles.getTrustProfiles().size(), 1);

    }

    @Test
    public void testSetEntities() {
        final CAEntity caEntity = new CAEntity();
        final List<CAEntity> listOfCAEntities = new ArrayList<CAEntity>();
        listOfCAEntities.add(caEntity);
        final Entity entity = new Entity();
        final List<Entity> listOfEntities = new ArrayList<Entity>();
        listOfEntities.add(entity);
        Entities entities = commandHandlerUtils.setEntities(EntityType.CA_ENTITY, listOfCAEntities);
        assertEquals(entities.getCAEntities().size(), 1);
        entities = commandHandlerUtils.setEntities(EntityType.ENTITY, listOfEntities);
        assertEquals(entities.getEntities().size(), 1);
    }

    @Test
    public void testGetProfileByType() {
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setId(1);
        certificateProfile.setName("rootcertprofile");
        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();
        certificateProfiles.add(certificateProfile);
        final Profiles profiles = new Profiles();
        profiles.setCertificateProfiles(certificateProfiles);
        List<? extends AbstractProfile> profile = commandHandlerUtils.getProfileByType(profiles, ProfileType.CERTIFICATE_PROFILE);
        assertEquals(profile.get(0).getName(), "rootcertprofile");
        profile = commandHandlerUtils.getProfileByType(profiles, ProfileType.ENTITY_PROFILE);
        profile = commandHandlerUtils.getProfileByType(profiles, ProfileType.TRUST_PROFILE);
    }

    @Test
    public void testGetAllProfiles() {
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setId(1);
        certificateProfile.setName("rootcertprofile");
        final List<CertificateProfile> listOfProfiles = new ArrayList<CertificateProfile>();
        listOfProfiles.add(certificateProfile);
        final List<AbstractProfile> profiles = commandHandlerUtils.getAllProfiles(listOfProfiles);
        assertEquals(profiles.size(), 1);
    }

    @Test
    public void testGetAllEntries() {
        final CAEntity caEntity = new CAEntity();
        final List<CAEntity> listOfEntities = new ArrayList<CAEntity>();
        listOfEntities.add(caEntity);
        final List<AbstractEntity> listAbstractEntities = commandHandlerUtils.getAllEntries(listOfEntities);
        assertEquals(listAbstractEntities.size(), 1);
    }

    @Test
    public void testGetProfilesFromInputXml() throws IOException {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        final String filePath = "src/test/resources/profiles.xml";
        properties.put("filePath", filePath);
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        final String content = new String(Files.readAllBytes(Paths.get(filePath)));
        Mockito.when(cliUtil.getFileContentFromCommandProperties(command.getProperties())).thenReturn(content);
        Profiles profiles = commandHandlerUtils.getProfilesFromInputXml(command);
        assertNotNull(profiles);
    }

    @Test(expected = CommonRuntimeException.class)
    public void testGetProfilesFromInputXmlCommonRuntimeException() {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        final URL url = getClass().getClassLoader().getResource("profiles.xml");
        properties.put("filePath", url.toString().substring(5));
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        commandHandlerUtils.getProfilesFromInputXml(command);

    }

    @Test
    public void testGetUpdatedProfilesFromInputXml() throws IOException {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put("filePath", "singleprofile.xml");
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        final String content = new String(Files.readAllBytes(Paths.get("src/test/resources/singleprofile.xml")));
        Mockito.when(cliUtil.getFileContentFromCommandProperties(command.getProperties())).thenReturn(content);
        Profiles profiles = commandHandlerUtils.getUpdatedProfilesFromInputXml(command);
        assertNotNull(profiles);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetUpdatedProfilesFromInputXmlException() throws IOException {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put("filePath", "singleprofile.xml");
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        commandHandlerUtils.getUpdatedProfilesFromInputXml(command);
    }

    @Test
    public void testGetEntitiesFromInputXml() throws IOException {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put("filePath", "singleprofile.xml");
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        final String filePath = "src/test/resources/singleprofile.xml";
        final String content = new String(Files.readAllBytes(Paths.get(filePath)));
        Mockito.when(cliUtil.getFileContentFromCommandProperties(command.getProperties())).thenReturn(content);
        Entities entities = commandHandlerUtils.getEntitiesFromInputXml(command);
        assertNotNull(entities);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testgetEntitiesFromInputXmlException() throws IOException {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put("filePath", "singleprofile.xml");
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        commandHandlerUtils.getEntitiesFromInputXml(command);
    }

    @Test
    public void testGetUpdatedEntitiesFromInputXml() throws IOException {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        final String filePath = "src/test/resources/profiles.xml";
        properties.put("filePath", filePath);
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        final String content = new String(Files.readAllBytes(Paths.get(filePath)));
        Mockito.when(cliUtil.getFileContentFromCommandProperties(command.getProperties())).thenReturn(content);
        Entities entities = commandHandlerUtils.getUpdatedEntitiesFromInputXml(command);
        assertNotNull(entities);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetUpdatedEntitiesFromInputXmlException() throws IOException {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        final URL url = getClass().getClassLoader().getResource("profiles.xml");
        properties.put("filePath", url.toString().substring(5));
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        commandHandlerUtils.getUpdatedEntitiesFromInputXml(command);
    }

    @Test
    public void testGetCertificateFromInputFile() throws IOException, CertificateException, IllegalArgumentException {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        final URL url = getClass().getClassLoader().getResource("MyRoot.crt");
        properties.put("filePath", url.toString().substring(5));
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        final X509Certificate certificate = commandHandlerUtils.getCertificateFromInputFile(command);
        assertNotNull(certificate);
    }

    @Test
    public void testGetCRLFromInputFile() throws Exception {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        final URL url = getClass().getClassLoader().getResource("testCA.crl");
        properties.put("filePath", url.toString().substring(5));
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        X509CRL x509Crl = commandHandlerUtils.getCRLFromInputFile(command);
        assertNotNull(x509Crl);
    }

    @Test(expected = CRLException.class)
    public void testGetCRLFromURLException() throws CRLException {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put("url", "d:");
        command = new PkiPropertyCommand();
        command.setProperties(properties);
        commandHandlerUtils.getCRLFromURL(command);
    }

    @Test
    public void testGetRevocationReasonUsingText() {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        command = new PkiPropertyCommand();
        properties.put(Constants.REVOCATION_REASON_TEXT, "keyCompromise");
        command.setProperties(properties);
        assertEquals(commandHandlerUtils.getRevocationReason(command), RevocationReason.KEY_COMPROMISE);
    }

    @Test
    public void testGetRevocationReasonUsingCode() {
        PkiPropertyCommand command;
        final Map<String, Object> properties = new HashMap<String, Object>();
        command = new PkiPropertyCommand();
        properties.put(Constants.REVOCATION_REASON_CODE, "1");
        command.setProperties(properties);
        assertEquals(commandHandlerUtils.getRevocationReason(command), RevocationReason.KEY_COMPROMISE);

    }

    @Test
    public void testGetInvalidityDateInGmt() {
        Date date = commandHandlerUtils.getInvalidityDateInGmt("2016-03-22 22:03:01");
        assertNotNull(date);
    }

    @Test(expected = CommonRuntimeException.class)
    public void testGetInvalidityDateInGmtException() {
        commandHandlerUtils.getInvalidityDateInGmt(Constants.EMPTY_STRING);
    }

    @Test
    public void testGetDateString() {
        final Date testDate = new Date();
        final String dateStr = commandHandlerUtils.getDateString(testDate);
        assertNotNull(dateStr);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetDateStringwithException() {
        final Date testDate = new Date("111");
        final String dateStr = commandHandlerUtils.getDateString(testDate);
        assertNotNull(dateStr);

    }

    @Test
    public void testGetFieldValues() {

        final List<String> iterable = new ArrayList<String>();
        iterable.add("C");
        iterable.add("A");
        iterable.add("E");
        iterable.add("B");
        final String expectedResult = commandHandlerUtils.getFieldValues(iterable, ";");
        assertNotNull(expectedResult);
    }

    @Test
    public void testGetAllSubjectFields() throws ParseException, DatatypeConfigurationException {
        final EntitySetUpData entitySetUpData = new EntitySetUpData();
        final Entity entity = entitySetUpData.getEntityForEqual();
        final Subject subject = entity.getEntityProfile().getSubject();
        final String expectedResult = commandHandlerUtils.getAllSubjectFields(subject);
        assertNotNull(expectedResult);

    }

    @Test
    public void testGetAllSubjectAltNameFields() throws ParseException, DatatypeConfigurationException {
        final EntitySetUpData entitySetUpData = new EntitySetUpData();
        final Entity entity = entitySetUpData.getEntityForEqual();
        final SubjectAltName subjectAltName = entity.getEntityProfile().getSubjectAltNameExtension();
        final String expectedResult = commandHandlerUtils.getAllSubjectAltNameFields(subjectAltName);
        assertNotNull(expectedResult);

    }

    @Test
    public void testGetKeyGenerationAlgorithmDetails() {
        final KeyGenerationAlgorithmSetUpData keyGenerationAlgorithmSetUpData = new KeyGenerationAlgorithmSetUpData();
        final Algorithm algorithm = keyGenerationAlgorithmSetUpData.getAlgorithmForEqual();
        final List<Algorithm> keyGenerationAlgorithms = new ArrayList<Algorithm>();
        keyGenerationAlgorithms.add(algorithm);
        final String expectedResult = commandHandlerUtils.getKeyGenerationAlgorithmDetails(keyGenerationAlgorithms);
        assertNotNull(expectedResult);

    }

    @Test
    public void testGetKeyGenerationAlgorithmNullDetails() {
        commandHandlerUtils.getKeyGenerationAlgorithmDetails(null);
    }

    @Test
    public void testGetKeyGenerationAlgorithmString() {
        final KeyGenerationAlgorithmSetUpData keyGenerationAlgorithmSetUpData = new KeyGenerationAlgorithmSetUpData();
        final Algorithm algorithm = keyGenerationAlgorithmSetUpData.getAlgorithmForEqual();
        final String expectedResult = commandHandlerUtils.getKeyGenerationAlgorithmString(algorithm);
        assertNotNull(expectedResult);

    }

    @Test
    public void testGetCertificateActiveStatus() {
        assertEquals(commandHandlerUtils.getCertificateStatus(Constants.CERTIFICATE_ACTIVE_STATUS), CertificateStatus.ACTIVE);
    }

    @Test
    public void testGetCertificateRevokedStatus() {
        assertEquals(commandHandlerUtils.getCertificateStatus(Constants.CERTIFICATE_REVOKED_STATUS), CertificateStatus.REVOKED);
    }

    @Test
    public void testGetCertificateExpiredStatus() {
        assertEquals(commandHandlerUtils.getCertificateStatus(Constants.CERTIFICATE_EXPIRED_STATUS), CertificateStatus.EXPIRED);
    }

    @Test
    public void testGetCertificateInactiveStatus() {
        assertEquals(commandHandlerUtils.getCertificateStatus(Constants.CERTIFICATE_INACTIVE_STATUS), CertificateStatus.INACTIVE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetCertificateStatusException() {
        commandHandlerUtils.getCertificateStatus(Constants.EMPTY_STRING);
    }
}
