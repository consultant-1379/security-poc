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
package com.ericsson.oss.itpf.security.credmsapi.api.model;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class EntityInfoTest {

	/**
	 * Test method for
	 * {@link com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo#EntityInfo(java.lang.String, java.lang.String)}
	 * .
	 */
	@Test
	public void testEntityInfoStringString() {

		EntityInfo entityInfo = new EntityInfo("entityName", "myOTP");

		assertTrue(entityInfo.getEntityName() == "entityName"
				&& entityInfo.getOneTimePassword() == "myOTP");
	}

	/**
	 * Test method for
	 * {@link com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo#getEntityName()}
	 * .
	 */
	@Test
	public void testGetEntityName() {
		EntityInfo entityInfo = new EntityInfo("entityName", "myOTP");

		assertTrue(entityInfo.getEntityName() == "entityName");
	}

	/**
	 * Test method for
	 * {@link com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo#setEntityName(java.lang.String)}
	 * .
	 */
	@Test
	public void testSetEntityName() {

		EntityInfo entityInfo = new EntityInfo();

		entityInfo.setEntityName("testEntityName");
		assertTrue(entityInfo.getEntityName() == "testEntityName");

	}

	/**
	 * Test method for
	 * {@link com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo#getOneTimePassword()}
	 * .
	 */
	@Test
	public void testGetOneTimePassword() {

		EntityInfo entityInfo = new EntityInfo("entityName", "myOTP");

		assertTrue(entityInfo.getOneTimePassword() == "myOTP");
	}

	/**
	 * Test method for
	 * {@link com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo#setOneTimePassword(java.lang.String)}
	 * .
	 */
	@Test
	public void testSetOneTimePassword() {

		EntityInfo entityInfo = new EntityInfo();

		entityInfo.setOneTimePassword("testMyOTP");
		assertTrue(entityInfo.getOneTimePassword() == "testMyOTP");
	}

	/**
	 * Test method for
	 * {@link com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo#isValid()}
	 * .
	 */
	@Test
	public void testIsValid() {

		EntityInfo entityInfo = new EntityInfo();
		assertTrue(!entityInfo.isValid());

		entityInfo.setEntityName("entityName");
		assertTrue(!entityInfo.isValid());

		entityInfo.setEntityName(null);
		entityInfo.setOneTimePassword("oneTimePassword");
		assertTrue(!entityInfo.isValid());

		entityInfo.setEntityName("entityName");
		assertTrue(entityInfo.isValid());

		entityInfo.setEntityName("");
		assertTrue(!entityInfo.isValid());

		entityInfo.setEntityName("entityName");
		entityInfo.setOneTimePassword("");
		assertTrue(!entityInfo.isValid());

		entityInfo.setEntityName("");
		assertTrue(!entityInfo.isValid());
	}

}
