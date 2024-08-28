package com.ericsson.oss.itpf.security.credmservice.profilesUpgrade;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfigurations;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

@RunWith(MockitoJUnitRunner.class)
public class CredMServiceUpdateProfilesManagerTest {

    @Mock
    SystemRecorderWrapper mockSysRec;

    @Mock
    CredMServiceCustomConfigurationManagementHandler mockCredMServiceCustomConfigurationManagementHandler;

    @InjectMocks
    CredMServiceProfilesUpdateManager beanUnderTest;

    @Test
    public void CredMServiceProfilesUpdateManagerTest() throws CustomConfigurationInvalidException, CustomConfigurationServiceException,
    CustomConfigurationAlreadyExistsException, CustomConfigurationNotFoundException {

        beanUnderTest.updatePkiCustomConfigurations();

        final CustomConfigurations cConfs = new CustomConfigurations();
        final List<CustomConfiguration> cConfList = new ArrayList<CustomConfiguration>();
        final CustomConfiguration cConfEntry1 = new CustomConfiguration();
        cConfEntry1.setId(1);
        cConfEntry1.setName("cvn");
        cConfEntry1.setNote("for test purpose");
        cConfEntry1.setValue("1");
        cConfEntry1.setOwner("credm");
        cConfList.add(cConfEntry1);
        cConfs.setCustomConfigurations(cConfList);
        Mockito.when(mockCredMServiceCustomConfigurationManagementHandler.getCredMServiceCustomConfigurations()).thenReturn(cConfs);

        assertTrue(!beanUnderTest.readAndCompareCvn());

        beanUnderTest.init(); //pkiCustomConfiguration null (zero, aka different)
        assertTrue(beanUnderTest.isInitDone());

        assertTrue(!beanUnderTest.readAndCompareCvn());
        beanUnderTest.updatePkiCustomConfigurations();

        //cvn zero to one
        final CertificateProfile cpXml = new CertificateProfile();
        cpXml.setName("cpXml");
        final CertificateProfile cpPki = new CertificateProfile();
        cpPki.setName("cpPki");
        CertificateProfile resultCP = beanUnderTest.checkCertificateProfileUpgradePath(cpXml, cpPki);
        assertTrue(resultCP.getName().equals((cpXml.getName())));

        final TrustProfile tpXml = new TrustProfile();
        tpXml.setName("tpXml");
        final TrustProfile tpPki = new TrustProfile();
        tpPki.setName("tpPki");
        TrustProfile resultTP = beanUnderTest.checkTrustProfileUpgradePath(tpXml, tpPki);
        assertTrue(resultTP == null);

        final EntityProfile epXml = new EntityProfile();
        epXml.setName("epXml");
        final EntityProfile epPki = new EntityProfile();
        epPki.setName("epPki");
        EntityProfile resultEP = beanUnderTest.checkEntityProfileUpgradePath(epXml, epPki);
        assertTrue(resultEP == null);
        epXml.setName("SCEPRA_IPSec_EP");
        resultEP = beanUnderTest.checkEntityProfileUpgradePath(epXml, epPki);
        assertTrue(resultEP.getName().equals(epXml.getName()));

        final CAEntity caXml = new CAEntity();
        caXml.setCertificateAuthority(new CertificateAuthority());
        final List<CrlGenerationInfo> crlGenerationInfoList = new ArrayList<CrlGenerationInfo>();
        crlGenerationInfoList.add(new CrlGenerationInfo());
        caXml.getCertificateAuthority().setCrlGenerationInfo(crlGenerationInfoList);
        final CAEntity caPki = new CAEntity();
        caPki.setCertificateAuthority(new CertificateAuthority());
        CAEntity resultCA = beanUnderTest.checkCAEntityUpgradePath(caXml, caPki);
        assertTrue(resultCA.equals(caXml));

        //cvn one to one
        Mockito.when(mockCredMServiceCustomConfigurationManagementHandler.getPkiCustomConfigurations()).thenReturn(cConfs);
        beanUnderTest.init(); //pkiCustomConfiguration equal
        beanUnderTest.updatePkiCustomConfigurations();

        resultCP = beanUnderTest.checkCertificateProfileUpgradePath(new CertificateProfile(), new CertificateProfile());
        assertTrue(resultCP == null);
        resultTP = beanUnderTest.checkTrustProfileUpgradePath(new TrustProfile(), new TrustProfile());
        assertTrue(resultTP == null);
        resultEP = beanUnderTest.checkEntityProfileUpgradePath(new EntityProfile(), new EntityProfile());
        assertTrue(resultEP == null);
        final CAEntity caXmlSame = new CAEntity();
        final CAEntity caPkiSame = new CAEntity();
        caXmlSame.setCertificateAuthority(new CertificateAuthority());
        caPkiSame.setCertificateAuthority(new CertificateAuthority());
        resultCA = beanUnderTest.checkCAEntityUpgradePath(caXmlSame, caPkiSame);
        assertTrue(resultCA == null);

        //cvn one to zero -> exception!!!
        //set cvn value from credm from 1 to 0
        final CustomConfigurations cConfZero = new CustomConfigurations();
        cConfZero.setCustomConfigurations(new ArrayList<CustomConfiguration>());
        final CustomConfiguration cConfEntryZero = new CustomConfiguration();
        cConfEntryZero.setValue("0");
        cConfEntryZero.setId(1);
        cConfEntryZero.setName("cvn");
        cConfEntryZero.setNote("for test purpose");
        cConfEntryZero.setOwner("credm");
        cConfZero.getCustomConfigurations().add(cConfEntryZero);
        Mockito.when(mockCredMServiceCustomConfigurationManagementHandler.getCredMServiceCustomConfigurations()).thenReturn(cConfZero);
        try {
            beanUnderTest.init();
            assertTrue(false);
        } catch (final CustomConfigurationInvalidException e) {
            assertTrue(true);
        }

        //readPki cvn config exceptions
        Mockito.when(mockCredMServiceCustomConfigurationManagementHandler.getPkiCustomConfigurations())
        .thenThrow(new CustomConfigurationNotFoundException()).thenThrow(new CustomConfigurationInvalidException())
        .thenThrow(new CustomConfigurationServiceException());
        try {
            beanUnderTest.init();
            assertTrue(false);
        } catch (final CustomConfigurationInvalidException e) {
            assertTrue(true);
        }
    }

    @Test(expected = CustomConfigurationInvalidException.class)
    public void testNullConfiguration() {
        beanUnderTest.init();
    }
}
