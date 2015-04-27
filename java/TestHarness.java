import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.NamingException;

import junit.framework.Assert;

import org.apache.log4j.Logger;
import org.apache.log4j.LogManager;
import org.junit.Test;

import com.template.adapter.idp.util.LDAPUtil;


public class TestHarness {

	public Logger log = Logger.getLogger(this.getClass());

	@Test
	public void Test() throws UnsupportedEncodingException {	
	}
	
	@Test
	public void LDAPTest() {
		Properties properties = new Properties();
		properties.setProperty("host", "ldap.forumsys.com:389");
		properties.setProperty("loginDN","cn=read-only-admin,dc=example,dc=com");
		properties.setProperty("loginPassword","password");
		properties.setProperty("baseDN","dc=example,dc=com");
		properties.setProperty("attribute","initials");
		
		LDAPUtil ldt = new LDAPUtil(properties);

		try {
			Assert.assertEquals("TS", ldt.getAttributeValue("Initials=TS"));
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
