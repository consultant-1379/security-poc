/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;

@RunWith(MockitoJUnitRunner.class)
public class ApplicationConfigurationTest {

    @Mock
    SystemRecorderWrapper systemRecorder;

    @Test
    public void isCENMGetPropertyTest() {
        System.setProperty("configuration.env.cloud.deployment", "TRUE");
        assertTrue(ApplicationConfiguration.isCENM());
    }

    @Test
    public void isCENMGetPropertyFailedTest() {
        System.clearProperty("configuration.env.cloud.deployment");
        assertFalse(ApplicationConfiguration.isCENM());
    }

    @Test
    public void isCENMGetPropertyFalseTest() {
        System.setProperty("configuration.env.cloud.deployment", "FALSE");
        assertFalse(ApplicationConfiguration.isCENM());
    }

    @Test
    public void isCENMGetPropertyOnCloudTest() throws ReflectiveOperationException {
        System.setProperty("configuration.env.cloud.deployment", "FALSE");
        updateEnv("CLOUD_DEPLOYMENT", "TRUE");
        assertTrue(ApplicationConfiguration.isCENM());
    }

    @Test
    public void isCENMGetPropertyOnCloudFalseTest() throws ReflectiveOperationException {
        System.setProperty("configuration.env.cloud.deployment", "FALSE");
        updateEnv("CLOUD_DEPLOYMENT", "FALSE");
        assertFalse(ApplicationConfiguration.isCENM());
    }

    private static void updateEnv(final String name, final String val) throws ReflectiveOperationException {
        final Map<String, String> env = System.getenv();
        final Field field = env.getClass().getDeclaredField("m");
        field.setAccessible(true);
        ((Map<String, String>) field.get(env)).put(name, val);
    }
}
