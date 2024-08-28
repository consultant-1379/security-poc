/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;

@RunWith(MockitoJUnitRunner.class)
public class CSRBuilderTest {

    @InjectMocks
    CSRBuilder cSRBuilder;

    @Mock
    Logger logger;

    @Test
    public void testGenerateCSR() throws IOException {

        final String data = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0NCk1JSUN3ekNDQWFzQ0FRQXdaakVMTUFrR0ExVUVCaE1DU1U0eEVqQVFCZ05WQkFnTUNWUmxiR0Z1WjJGdVlURVQNCk1CRUdBMVVFQnd3S1NIbGtaWEppWVdKaFpERU1NQW9HQTFVRUNnd0RWRU5UTVJFd0R3WURWUVFMREFoRlVrbEQNClUxTlBUakVOTUFzR0ExVUVBd3dFVWtGcVlUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0MNCmdnRUJBTjZxNVJBVFA2TkhoSjM1Si96WDN0R0I3VW1JMXlUUW9lWDBqOU1LN0VqUzBkajJDb3hiOWRwa1ZTcVQNCnZFOEFmSndtaFIzVTR2c1ZjSytGNjExYTcrZTdCdUJUSi9lRDF5Sk1aQ2NwaXl1cUZoQ0JlaHJYTGFtSXN2TkENCktOeEd6dlJxdzZGK3FvY09nNWxGaHIyNnAyUi9VbU9ZUlo4aTIwb0pTb3FRcVdhdEVVRVZmaTlqUmxoUHE2bWkNCmFDUmFGc3dmWjZtQXI3eHh0Vnhsb1A1ZVNRS1pGbGhHaTVETEx0RXFCZVJQV2l6SC9TekJTS1BhZFpJTVdlNWUNCnN1a2lYYXV6VEc1bFBKWWtRakZEN3BjY2o4U3R6UytzWlBtdTMzYndxVExJSWd0UkxIeUhPWGd4VDNvMmhNSEsNCkNrVDhZZ3NVZThnTTFyUnF1MGJXdHNGRGtyRUNBd0VBQWFBWU1CWUdDU3FHU0liM0RRRUpCekVKREFkMFpYTjANCk1USXpNQTBHQ1NxR1NJYjNEUUVCQlFVQUE0SUJBUURWZXF0VlBKaTNqQU9YYWRqTTlZRlVVTGNxQks4ODNtWG8NCkloOGRBaDU2U1RWVXBvMWErREtmT1FVRGhIUWsrL01OVE9nd3lVSFl2U2djQ1NaTW1XSHhjL0h5eDh0WjhmcWcNClQySEF0dmhYeU9nZjJaZCtxQWIza0t2bm5HdVJGNkNCb1RqOHFNRThCbWRkMTkrNnppNUVvUGdEUUluR3FPUTQNCnpKcHBzNE82QkJicG8ydmFSMWJCMlRSSDcvNTJkTisrUFkzK0tyQ2x0MmprcXJwSW5ISDBNR05vTitmSXMvb3YNCmYyU2NKRDNQWGVxVWZwbXhuSkp1elBraEZhRFpNNEozR2VFZExOdEluN3UxMWFiZW5URHhOY0Q4dHRVSWRMMlQNCjdWQUMzRVdSUU1ZTWdSTnM5V1ZqKzJzSnFNc1UyaDE1QjZRWjVOeU9TbUo5SnFKT0JRNHQNCi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQ==";
        final byte[] bytedata = Base64.decode(data);

        final CertificateRequest certificateRequest = cSRBuilder.generateCSR(new String(bytedata));
        assertNotNull(certificateRequest);
    }

}
