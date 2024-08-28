package com.ericsson.oss.services.cm.admin.cli.utils;

import com.ericsson.oss.services.cm.admin.cli.manager.ParameterManager;
import com.ericsson.oss.services.cm.admin.domain.SnmpData;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;

@RunWith(MockitoJUnitRunner.class)
public class ParameterValueMapperTest {

    @Mock
    private FilterContext filterContext;

    @Mock
    private ParameterManager parameterManager;

    @Test
    public void getSuitableConverterTestForNonPasswordParameter() {
        Mockito.when(filterContext.getParameterManager()).thenReturn(parameterManager);
        Mockito.when(filterContext.getParameterName()).thenReturn("AP_SNMP_AUDIT_TIME");
        Mockito.when(parameterManager.isPasswordParameter(filterContext.getParameterName())).thenReturn(false);
        ParameterValueConverter actual = ParameterValueMapper.getSuitableConverter(filterContext);
        Assert.assertEquals(actual, ParameterValueDefaultConverter.getInstance());
    }

    @Test
    public void getSuitableConverterTest1ForPasswordParameter() {
        Mockito.when(filterContext.getParameterManager()).thenReturn(parameterManager);
        Mockito.when(filterContext.getParameterName()).thenReturn("NODE_SNMP_INIT_SECURITY");
        Mockito.when(parameterManager.isPasswordParameter(filterContext.getParameterName())).thenReturn(true);
        Mockito.when(parameterManager.getDataType(filterContext.getParameterName())).thenReturn(SnmpData.class);
        ParameterValueConverter actual = ParameterValueMapper.getSuitableConverter(filterContext);
        Assert.assertEquals(actual, ParameterValueSnmpConverter.getInstance());
    }

    @Test
    public void getSuitableConverterTest2ForPasswordParameter() {
        Mockito.when(filterContext.getParameterManager()).thenReturn(parameterManager);
        Mockito.when(filterContext.getParameterName()).thenReturn("BOGUS_1");
        Mockito.when(parameterManager.isPasswordParameter(filterContext.getParameterName())).thenReturn(true);
        Mockito.when(parameterManager.getDataType(filterContext.getParameterName())).thenReturn(String.class);
        ParameterValueConverter actual = ParameterValueMapper.getSuitableConverter(filterContext);
        Assert.assertEquals(actual, ParameterValueDefaultConverter.getInstance());
    }

    @Test
    public void testConstructorIsPrivate() throws Exception {
        Constructor<ParameterValueMapper> constructor = ParameterValueMapper.class.getDeclaredConstructor();
        Assert.assertTrue(Modifier.isPrivate(constructor.getModifiers()));
    }

}