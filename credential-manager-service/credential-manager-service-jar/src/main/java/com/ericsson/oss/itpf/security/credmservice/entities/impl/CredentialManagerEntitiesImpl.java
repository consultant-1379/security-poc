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
package com.ericsson.oss.itpf.security.credmservice.entities.impl;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.credmservice.entities.api.CredentialManagerEntities;
import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.*;

public class CredentialManagerEntitiesImpl implements CredentialManagerEntities {

	private static final long serialVersionUID = -1339739185679099076L;
	private final List<XmlEntity> entities = new ArrayList<XmlEntity>();
	private final List<XmlCAEntity> CAentities = new ArrayList<XmlCAEntity>();

	/**
	 * 
	 */
	public CredentialManagerEntitiesImpl(final Object entitiesObj)
			throws CredentialManagerEntitiesException {

		XmlPKIEntities pkiEntities;

		if (entitiesObj != null && entitiesObj instanceof XmlPKIEntities) {
			pkiEntities = (XmlPKIEntities) entitiesObj;
		} else {
			throw new CredentialManagerEntitiesException(
					"Loading information of XML Applications Type...[Failed]");
		}

		if (pkiEntities.getEntities() != null) {
			for (final XmlEntity entity : pkiEntities.getEntities().getEntity()) {
				if (entity != null) {
					entities.add(entity);
				}
			}
		}

		if (pkiEntities.getCAEntities() != null) {
			for (final XmlCAEntity CAentity : pkiEntities.getCAEntities()
					.getCAEntity()) {
				if (CAentity != null) {
					CAentities.add(CAentity);
				}
			}
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credmservice.entities.api.
	 * CredentialManagerEntities#getEntities()
	 */
	@Override
	public List<XmlEntity> getEntities() {

		return entities;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credmservice.entities.api.
	 * CredentialManagerEntities#getCAEntities()
	 */
	@Override
	public List<XmlCAEntity> getCAEntities() {

		return CAentities;
	}

}
