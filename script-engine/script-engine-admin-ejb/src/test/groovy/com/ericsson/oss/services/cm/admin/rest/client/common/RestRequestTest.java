package com.ericsson.oss.services.cm.admin.rest.client.common;

import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Optional;

public class RestRequestTest {

    private HttpResponse httpResponse = Mockito.mock(HttpResponse.class);

    private StatusLine statusLine = Mockito.mock(StatusLine.class);

    @Test
    public void testSuccessResponseCode() {
        Mockito.when(statusLine.getStatusCode()).thenReturn(200);
        Mockito.when(httpResponse.getStatusLine()).thenReturn(statusLine);
        RestResponse actual = new RestResponse(httpResponse);
        Assert.assertTrue(actual.isValid());
        Assert.assertEquals(Optional.empty(), actual.getData());
        Assert.assertEquals(Optional.empty(), actual.getErrorDetails());
    }

    @Test
    public void testValidRangeResponseCode1() {
        Mockito.when(statusLine.getStatusCode()).thenReturn(201);
        Mockito.when(httpResponse.getStatusLine()).thenReturn(statusLine);
        RestResponse actual = new RestResponse(httpResponse);
        Assert.assertTrue(actual.isValid());
    }

    @Test
    public void testValidRangeResponseCode2() {
        Mockito.when(statusLine.getStatusCode()).thenReturn(299);
        Mockito.when(httpResponse.getStatusLine()).thenReturn(statusLine);
        RestResponse actual = new RestResponse(httpResponse);
        Assert.assertTrue(actual.isValid());
    }

    @Test
    public void testValidRangeResponseCode3() {
        Mockito.when(statusLine.getStatusCode()).thenReturn(300);
        Mockito.when(httpResponse.getStatusLine()).thenReturn(statusLine);
        RestResponse actual = new RestResponse(httpResponse);
        Assert.assertFalse(actual.isValid());
    }

    @Test
    public void testValidRangeResponseCode4() {
        Mockito.when(statusLine.getStatusCode()).thenReturn(500);
        Mockito.when(httpResponse.getStatusLine()).thenReturn(statusLine);
        RestResponse actual = new RestResponse(httpResponse);
        Assert.assertFalse(actual.isValid());
    }

}