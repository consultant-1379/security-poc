/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.ejb.startup;

import javax.management.AttributeNotFoundException;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MalformedObjectNameException;
import javax.management.ReflectionException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.ericsson.oss.itpf.security.credmservice.util.MBeanManager;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ MBeanManager.class })
public class CredMServiceConfiguratorTest {
    @InjectMocks
    CredMServiceConfigurator credMServiceConfigurator;


    @Test
    public void test()
            throws MalformedObjectNameException, AttributeNotFoundException, InstanceNotFoundException, MBeanException, ReflectionException {
        PowerMockito.mockStatic(MBeanManager.class);
        PowerMockito.when(MBeanManager.getPKIManagerDeployed()).thenThrow(new AttributeNotFoundException());

        credMServiceConfigurator.timeoutHandler(null);
    }

    @Test
    public void test1()
            throws MalformedObjectNameException, AttributeNotFoundException, InstanceNotFoundException, MBeanException, ReflectionException {
        PowerMockito.mockStatic(MBeanManager.class);
        PowerMockito.when(MBeanManager.getPKIManagerDeployed()).thenThrow(new RuntimeException());
        credMServiceConfigurator.timeoutHandler(null);
    }
}
