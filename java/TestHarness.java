import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.NamingException;

import junit.framework.Assert;

import org.apache.log4j.Logger;
import org.apache.log4j.LogManager;
import org.junit.Test;

public class TestHarness {

	public Logger log = Logger.getLogger(this.getClass());

	@Test
	public void Test() {	
	}
	
	@Test
	public void FilterTest() {
		String userName = "user1-3@detfed1.adambradleyconsulting.com";
		String filter = "userPrincipalName=${username}".replace("${username}", userName);
		
	}
}
