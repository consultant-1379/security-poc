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
 *----------------------------------------------------------------------------
package com.ericsson.oss.itpf.security.pki.manager.tdps.event.notification.handlers;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;


import org.slf4j.Logger;

import  com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;


@RunWith(MockitoJUnitRunner.class)
public class TestTDPSAcknowledgementRequestHandler
{

	@InjectMocks
	TDPSAcknowledgementRequestHandler tdpsAcknowledgementRequestHandler;
	
	
	@Mock
	TDPSAcknowledgementEvent tdpsAcknowledgementEvent;
	
	 @Mock
	 Logger logger;
	
	@Mock
	TDPSCertificateInfo tdpsCertificateInfo;
	
	//private List<TDPSCertificateInfo>  listTDPSCertificateInfo ;
	
	
	
	@Test
	public void testHandle()
	{
     	System.out.println("testHandle");
		final String entityName = "entityName";
		final String issuerName = "issuerName";
		final String serialNumber = "serialNumber";
		//setupData();
		
		//TDPSAcknowledgementEvent tdpsAcknowledgementEvent = new TDPSAcknowledgementEvent();
		//Mockito.when(tdpsAcknowledgementEvent.getTdpsOperationType()).thenReturn(TDPSOperationType.PUBLISH);
		
		
		//Mockito.when(tdpsAcknowledgementEvent.getTdpsCertificateInfoList()).thenReturn(listTDPSCertificateInfo);
		Mockito.when(tdpsCertificateInfo.getTdpsEntityType()).thenReturn(TDPSEntityType.ENTITY);
		Mockito.when(tdpsCertificateInfo.getEntityName()).thenReturn(entityName);
		Mockito.when(tdpsCertificateInfo.getIssuerName()).thenReturn(issuerName);
		Mockito.when(tdpsCertificateInfo.getSerialNumber()).thenReturn(serialNumber);
		
		
		
		//tdpsAcknowledgementRequestHandler.handle(tdpsAcknowledgementEvent);
		
	}
	
	public void setupData()
	{
		
		listTDPSCertificateInfo = new ArrayList<TDPSCertificateInfo>();
		listTDPSCertificateInfo.add(tdpsCertificateInfo);
		
	}
}
 */

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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.handlers;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.PersistenceException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers.TDPSEntityTypeMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.handlers.TDPSAcknowledgementRequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.TrustDistributionLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.*;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;

@RunWith(MockitoJUnitRunner.class)
public class TDPSAcknowledgementRequestHandlerTest {

    @InjectMocks
    TDPSAcknowledgementRequestHandler tdpsAcknowledgementRequestHandler;

    @Mock
    TDPSAcknowledgementEvent tdpsAcknowledgementEvent;

    @Mock
    Logger logger;

    @Mock
    TDPSCertificateInfo tdpsCertificateInfo;

    @Mock
    TDPSEntityTypeMapper tDPSEntityTypeMapper;

    @Mock
    TrustDistributionLocalService trustDistributionLocalService;

    @Test
    public void testHandle() {

        setupData();

        Mockito.when(tdpsAcknowledgementEvent.getResponseType()).thenReturn(TDPSResponseType.SUCCESS);
        Mockito.when(tdpsAcknowledgementEvent.getTdpsOperationType()).thenReturn(TDPSOperationType.PUBLISH);

        Mockito.when(tDPSEntityTypeMapper.fromModel(tdpsCertificateInfo.getTdpsEntityType())).thenReturn(EntityType.ENTITY);

        tdpsAcknowledgementRequestHandler.handle(tdpsAcknowledgementEvent);
        Mockito.verify(tdpsAcknowledgementEvent).getTdpsOperationType();
    }

    @Test
    public void testHandleFailureResponse() {

        setupData();

        Mockito.when(tdpsAcknowledgementEvent.getResponseType()).thenReturn(TDPSResponseType.FAILURE);
        tdpsAcknowledgementRequestHandler.handle(tdpsAcknowledgementEvent);
        Mockito.verify(logger).info("Negative acknowledgement for TDPS due to {} ", tdpsAcknowledgementEvent.getResponseType().toString());

    }

    @Test
    public void testHandleCertificateException() throws EntityNotFoundException, CertificateException, PersistenceException, IOException {

        setupData();

        Mockito.when(tdpsAcknowledgementEvent.getResponseType()).thenReturn(TDPSResponseType.SUCCESS);
        Mockito.when(tdpsCertificateInfo.getEntityName()).thenThrow(new EntityNotFoundException());
        Mockito.when(tDPSEntityTypeMapper.fromModel(tdpsCertificateInfo.getTdpsEntityType())).thenReturn(EntityType.ENTITY);

        tdpsAcknowledgementRequestHandler.handle(tdpsAcknowledgementEvent);
        Mockito.verify(tdpsAcknowledgementEvent).getTdpsOperationType();
    }

    public void setupData() {

        final String entityName = "entityName";
        final String issuerName = "issuerName";
        final String serialNumber = "serialNumber";

        List<TDPSCertificateInfo> listTDPSCertificateInfo = new ArrayList<TDPSCertificateInfo>();
        Mockito.when(tdpsCertificateInfo.getTdpsEntityType()).thenReturn(TDPSEntityType.ENTITY);
        Mockito.when(tdpsCertificateInfo.getEntityName()).thenReturn(entityName);
        Mockito.when(tdpsCertificateInfo.getIssuerName()).thenReturn(issuerName);
        Mockito.when(tdpsCertificateInfo.getSerialNumber()).thenReturn(serialNumber);

        listTDPSCertificateInfo.add(tdpsCertificateInfo);

        Mockito.when(tdpsAcknowledgementEvent.getTdpsCertificateInfoList()).thenReturn(listTDPSCertificateInfo);

    }

}
