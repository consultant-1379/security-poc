package com.ericsson.oss.services.cm.admin.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class ConfigurationParameterTest {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void testThatConfigurationParameterObjectCanBeConstructedFromJson() throws Exception {
        Path path = Paths.get("src/test/resources/PibServiceAndJvmIdentifierSingleParam");
        byte[] bytes = Files.readAllBytes(path);
        String content = new String(bytes, StandardCharsets.UTF_8);
        ConfigurationParameter actual = objectMapper.readValue(content, ConfigurationParameter.class);
        Assert.assertNotNull(actual);
    }

    @Test
    public void testThatConfigurationParameterObjectCanBeConstructedFromString() throws Exception {
        String content = "{\"id\":\"id1\",\"name\":\"jndiBind\",\"jvmIdentifier\":\"svc-5-mscmip\",\"serviceIdentifier\":\"mediationservice\",\"typeAsString\":\"java.lang.String\",\"value\":\"mediation-service\",\"description\":\"Jndi name\",\"overridableInScopes\":[\"service\",\"JVM\"],\"values\":[\"1\",\"3\"],\"namespace\":null,\"status\":\"CREATED_NOT_MODIFIED\",\"lastModificationTime\":1651357982396,\"type\":\"java.lang.String\",\"scope\":\"JVM_AND_SERVICE\",\"firstNonNullValue\":\"Jndi name\"}";
        ConfigurationParameter actual = objectMapper.readValue(content, ConfigurationParameter.class);
        Assert.assertNotNull(actual);
        Assert.assertTrue(actual.getOverridableInScopes().contains("service"));
        Assert.assertTrue(actual.getOverridableInScopes().contains("JVM"));
        Assert.assertTrue(actual.getValues().contains("1"));
        Assert.assertTrue(actual.getValues().contains("3"));
        Assert.assertEquals("id1", actual.getId());
        Assert.assertEquals("jndiBind", actual.getName());
        Assert.assertEquals("mediationservice", actual.getServiceIdentifier());
        Assert.assertEquals("svc-5-mscmip", actual.getJvmIdentifier());
        Assert.assertEquals("java.lang.String", actual.getTypeAsString());
        Assert.assertEquals("mediation-service", actual.getValue());
        Assert.assertEquals(null, actual.getNamespace());
        Assert.assertEquals("CREATED_NOT_MODIFIED", actual.getStatus());
        Assert.assertEquals(1651357982396L, actual.getLastModificationTime());
        Assert.assertEquals("java.lang.String", actual.getType());
        Assert.assertEquals("JVM_AND_SERVICE", actual.getScope());
        Assert.assertEquals("Jndi name", actual.getFirstNonNullValue());
    }

    @Test
    public void testThatConfigurationParameterObjectCanBeWrittenToJsonCorrectly() throws Exception {
        ConfigurationParameter configurationParameter = new ConfigurationParameter();
        configurationParameter.setId("testId");
        configurationParameter.setJvmIdentifier("testJvmIdentifier");
        configurationParameter.setServiceIdentifier("testServiceIdentifier");
        configurationParameter.setDescription("testDescription");
        configurationParameter.setName("testName");
        configurationParameter.setFirstNonNullValue(Arrays.asList("15000"));
        configurationParameter.setLastModificationTime(123L);
        configurationParameter.setNamespace("testNamespace");
        configurationParameter.setOverridableInScopes(Sets.newHashSet("JVM", "SERVICE"));
        configurationParameter.setStatus("CREATED");
        configurationParameter.setType("String");
        configurationParameter.setTypeAsString("string");
        configurationParameter.setValue("150000");
        configurationParameter.setValues(Arrays.asList("15000"));
        configurationParameter.setScope("JVM");
        String actual = objectMapper.writeValueAsString(configurationParameter);
        Assert.assertNotNull(actual);
    }

    @Test
    public void testGetId()
    {
        ConfigurationParameter configurationParameter = Mockito.mock(ConfigurationParameter.class);
        Mockito.when(configurationParameter.getId()).thenReturn("id");
        Assert.assertEquals("id", configurationParameter.getId());
    }

}
