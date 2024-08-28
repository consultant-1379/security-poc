package com.ericsson.oss.itpf.security.credmsapi.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.JNDIResolver;

/**
 * Created by enmadmin on 3/17/15.
 */
public class Main {

	private static final Logger logger = LogManager.getLogger(Main.class);
	public static void main(final String[] args) {
		logger.info(new JNDIResolver().resolveCredMService().hello("Domitillo"));
	}
}
