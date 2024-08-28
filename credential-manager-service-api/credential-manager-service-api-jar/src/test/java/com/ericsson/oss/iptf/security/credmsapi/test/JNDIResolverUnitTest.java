package com.ericsson.oss.iptf.security.credmsapi.test;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import com.ericsson.oss.itpf.security.credmsapi.JNDIResolver;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;

@RunWith(JUnit4.class)
public class JNDIResolverUnitTest {

//	private final static Logger LOG = LoggerFactory
//			.getLogger(JNDIResolverUnitTest.class);

	@Test
	public void testJNDIResolverException() {
		

	try {
		CredMService obj = new JNDIResolver().resolveCredMService();
		        assert( false);
			} catch (IllegalStateException e) {
				assert (true);
			}
	}
}
