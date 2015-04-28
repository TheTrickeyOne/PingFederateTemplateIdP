package com.template.adapter.idp.util;

import java.util.Hashtable;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.HasControls;

import org.apache.log4j.Logger;

//LDAP
import com.pingidentity.access.DataSourceAccessor;
import java.util.ArrayList;
import java.util.List;
import javax.naming.directory.SearchControls;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.domain.LdapDataSource;
import org.sourceid.saml20.domain.datasource.info.LdapInfo;
import org.sourceid.util.log.AttributeMap;

public class LDAPUtil {

    private Logger log = Logger.getLogger(this.getClass());
	private Properties properties;

	public LDAPUtil() {
	}
	
	public LDAPUtil(Properties properties) {
		this.properties = properties;
	}

	public LDAPUtil(Properties properties, Logger log) {
		this.properties = properties;
		this.log = log;
	}
	
	public String getAttributeValue(String filter) throws NamingException {
		Hashtable env = new Hashtable();
		env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, "ldap://" + properties.getProperty("host"));		
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, properties.getProperty("loginDN")); // specify the username
		env.put(Context.SECURITY_CREDENTIALS, properties.getProperty("loginPassword"));           // specify the password
		DirContext ctx = new InitialDirContext(env);
		
		SearchControls ctls = new SearchControls();
		ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		NamingEnumeration results = ctx.search(properties.getProperty("baseDN"), filter, ctls);
		
	    StringBuffer sb = new StringBuffer();

	    if (results.hasMore())
	    {
            SearchResult res = (SearchResult) results.next();
            Attributes attrs = res.getAttributes();   
            Attribute attribute = res.getAttributes().get(properties.getProperty("attribute")); 
            
            String attributeValue = (String) attribute.get();
            if (attributeValue != null) {
            	return attributeValue;        
            }
        }
	    
	    return null;
	 
	}
}
