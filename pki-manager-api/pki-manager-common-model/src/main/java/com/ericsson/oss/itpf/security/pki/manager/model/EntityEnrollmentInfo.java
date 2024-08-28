/*------------------------------------------------------------------------------
 ********************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 ********************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.manager.model;

import java.io.Serializable;
import java.security.cert.X509Certificate;

import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

/**
 * This class holds the information required for node enrollment.
 * 
 */
public class EntityEnrollmentInfo implements Serializable {

    
    /**
	 * 
	 */
	private static final long serialVersionUID = -9062779411955121277L;
	
	private EnrollmentInfo enrollmentInfo;
	private Entity entity;
	
	
	public EnrollmentInfo getEnrollmentInfo() {
		return enrollmentInfo;
	}
	public void setEnrollmentInfo(EnrollmentInfo enrollmentInfo) {
		this.enrollmentInfo = enrollmentInfo;
	}
	public Entity getEntity() {
		return entity;
	}
	public void setEntity(Entity entity) {
		this.entity = entity;
	}

	

    
}
