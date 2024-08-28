package com.ericsson.oss.itpf.security.credmservice.profilesUpgrade;

import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfigurations;
import com.ericsson.oss.services.security.pkimock.impl.MockCustomConfigurationManagementServiceImpl;

@RunWith(MockitoJUnitRunner.class)
public class CredMServiceUpdateCustomConfigsTest {

    @Mock
    MockCustomConfigurationManagementServiceImpl customConfigurationManagementService;

    @InjectMocks
    CredMServiceCustomConfigurationManagementHandler TestedCredMServiceCustomConfigurationManagementHandler = new CredMServiceCustomConfigurationManagementHandler();

    @Before
    public void setup() {

        this.customConfigurationManagementService = new MockCustomConfigurationManagementServiceImpl();
        this.customConfigurationManagementService.initCollections();
        Field pkiCustomConfigurationManagerField;
        try {
            pkiCustomConfigurationManagerField = CredMServiceCustomConfigurationManagementHandler.class
                    .getDeclaredField("mockCustomConfigurationManagementService");
            pkiCustomConfigurationManagerField.setAccessible(true);
            pkiCustomConfigurationManagerField.set(this.TestedCredMServiceCustomConfigurationManagementHandler,
                    this.customConfigurationManagementService);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            e.printStackTrace();
        }

    }

    @Test
    public void CredMServiceCustomConfigurationManagementHandlerTest() throws CustomConfigurationNotFoundException,
            CustomConfigurationInvalidException, CustomConfigurationServiceException, CustomConfigurationAlreadyExistsException {

        //if service is not installed the property file for credm configuration to be read will not exist
        //on the other hand if it was the asserts will fail

        CustomConfigurations credmConfs = TestedCredMServiceCustomConfigurationManagementHandler.getCredMServiceCustomConfigurations();
        //assertTrue(credmConfs == null);

        //We cannot trust the properties file, so we create the credm configuration
        final CustomConfiguration cConfEntry1 = new CustomConfiguration();
        cConfEntry1.setName("cvn");
        cConfEntry1.setOwner("credm");
        cConfEntry1.setId(0);
        cConfEntry1.setNote("for_test_purposes");
        cConfEntry1.setValue("0");
        final CustomConfiguration cConfEntry2 = new CustomConfiguration();
        cConfEntry2.setName("bsn");
        cConfEntry2.setOwner("credm");
        cConfEntry2.setId(1);
        cConfEntry2.setNote("for_test_purposes");
        cConfEntry2.setValue("0");

        final List<CustomConfiguration> cConfList = new ArrayList<CustomConfiguration>();
        cConfList.add(cConfEntry1);
        cConfList.add(cConfEntry2);
        credmConfs = new CustomConfigurations();
        credmConfs.setCustomConfigurations(cConfList);

        //At this point the custom config collection on mock is empty
        CustomConfigurations pkiConfs = TestedCredMServiceCustomConfigurationManagementHandler.getPkiCustomConfigurations();
        assertTrue(pkiConfs == null);

        //Set collection content with what was read on the cvn.properties (actually mocked)
        //then the content is read and it is expected to have that content from mock-pki
        TestedCredMServiceCustomConfigurationManagementHandler.setPkiCustomConfigurationsUpdate(credmConfs);
        pkiConfs = TestedCredMServiceCustomConfigurationManagementHandler.getPkiCustomConfigurations();
        assertTrue(pkiConfs.getCustomConfigurations().size() == 1);
        for (final CustomConfiguration cConfEntry : pkiConfs.getCustomConfigurations()) {
            assertTrue(cConfEntry.getOwner().equals("credm"));
            if (cConfEntry.getName().equals(cConfEntry1.getName())) {
                assertTrue(cConfEntry.getValue().equals(cConfEntry1.getValue()));
            }
            if (cConfEntry.getName().equals(cConfEntry2.getName())) {
                assertTrue(cConfEntry.getValue().equals(cConfEntry2.getValue()));
            }
        }

        //Content is re-read (same-version)
        pkiConfs = TestedCredMServiceCustomConfigurationManagementHandler.getPkiCustomConfigurations();
        for (final CustomConfiguration cConfEntry : pkiConfs.getCustomConfigurations()) {
            if (cConfEntry.getName().equals(cConfEntry1.getName())) {
                assertTrue(cConfEntry.getValue().equals(cConfEntry1.getValue()));
            }
            if (cConfEntry.getName().equals(cConfEntry2.getName())) {
                assertTrue(cConfEntry.getValue().equals(cConfEntry2.getValue()));
            }
        }

        //Values changed
        cConfEntry1.setValue("1");
        TestedCredMServiceCustomConfigurationManagementHandler.setPkiCustomConfigurationsUpdate(credmConfs);
        pkiConfs = TestedCredMServiceCustomConfigurationManagementHandler.getPkiCustomConfigurations();
        assertTrue(pkiConfs.getCustomConfigurations().size() == 1);
        for (final CustomConfiguration cConfEntry : pkiConfs.getCustomConfigurations()) {
            assertTrue(cConfEntry.getOwner().equals("credm"));
            if (cConfEntry.getName().equals(cConfEntry1.getName())) {
                assertTrue(cConfEntry.getValue().equals(cConfEntry1.getValue()));
            }
            if (cConfEntry.getName().equals(cConfEntry2.getName())) {
                assertTrue(cConfEntry.getValue().equals(cConfEntry2.getValue()));
            }
        }

        //Fun fact: if I set an inferior value it is set without problem
        //should not this be allowed?
        cConfEntry1.setValue("0");
        TestedCredMServiceCustomConfigurationManagementHandler.setPkiCustomConfigurationsUpdate(credmConfs);
        pkiConfs = TestedCredMServiceCustomConfigurationManagementHandler.getPkiCustomConfigurations();
        assertTrue(pkiConfs.getCustomConfigurations().size() == 1);
        for (final CustomConfiguration cConfEntry : pkiConfs.getCustomConfigurations()) {
            assertTrue(cConfEntry.getOwner().equals("credm"));
            if (cConfEntry.getName().equals(cConfEntry1.getName())) {
                assertTrue(cConfEntry.getValue().equals(cConfEntry1.getValue()));
            }
            if (cConfEntry.getName().equals(cConfEntry2.getName())) {
                assertTrue(cConfEntry.getValue().equals(cConfEntry2.getValue()));
            }
        }
    }

}
