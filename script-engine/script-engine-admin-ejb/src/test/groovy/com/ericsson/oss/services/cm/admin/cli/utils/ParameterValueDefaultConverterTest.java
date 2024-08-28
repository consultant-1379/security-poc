package com.ericsson.oss.services.cm.admin.cli.utils;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class ParameterValueDefaultConverterTest {

    @Mock
    private FilterContext filterContext;

    private ParameterValueDefaultConverter parameterValueDefaultConverter = new ParameterValueDefaultConverter();

    @Test
    public void convertTest() {
        Mockito.when(filterContext.getParameterValue()).thenReturn("02:30");
        String actual = parameterValueDefaultConverter.convert(filterContext);
        Assert.assertEquals("02:30", actual);
    }

    @Test
    public void convertTest1() {
        Mockito.when(filterContext.getParameterValue()).thenReturn("[\"ONE_MIN\",\"FIVE_MIN\",\"FIFTEEN_MIN\",\"THIRTY_MIN\",\"ONE_HOUR\",\"TWELVE_HOUR\"]");
        String actual = parameterValueDefaultConverter.convert(filterContext);
        Assert.assertEquals("[ONE_MIN,FIVE_MIN,FIFTEEN_MIN,THIRTY_MIN,ONE_HOUR,TWELVE_HOUR]", actual);
    }

    @Test
    public void convertTest2() {
        Mockito.when(filterContext.getParameterValue()).thenReturn("[\"FLOW_CONTROL_PERIOD:20\",\"//APG_MED/SyncApgLargeNodeFlow/1.0.0:4\"]");
        String actual = parameterValueDefaultConverter.convert(filterContext);
        Assert.assertEquals("{FLOW_CONTROL_PERIOD:20,//APG_MED/SyncApgLargeNodeFlow/1.0.0:4}", actual);
    }

}