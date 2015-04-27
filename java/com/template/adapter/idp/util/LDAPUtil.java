package com.template.adapter.idp.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import javax.naming.Name;
import javax.naming.NameClassPair;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class LDAPUtil
{
  private static Log log = LogFactory.getLog(LDAPUtil.class);
  private static final String SFUSERID_KEY = "userId";
  private static final String SFPASSWORD_KEY = "sfPassword";
  private static final String REGX_TAG_START = "\\$\\{";
  private static final String REGX_TAG_END = "\\}";
  
  private static String substituteValues(String original, Map substitutionValuesMap)
  {
    for (Iterator i = substitutionValuesMap.entrySet().iterator(); i.hasNext();)
    {
      Map.Entry entry = (Map.Entry)i.next();
      StringBuffer tag = new StringBuffer("\\$\\{").append(entry.getKey()).append("\\}");
      original = original.replaceAll(tag.toString(), entry.getValue().toString());
    }
    return original;
  }
  
  public NamingEnumeration<SearchResult> doLDAPSearch(ConnectionInfo connInfo, String searchBase, String filter, int searchScope, String[] attrs, int countLimit)
    throws NamingException
  {
    DirContext dirContext = null;
    SearchResult searchResult = null;
    NamingEnumeration<SearchResult> results = null;
    try
    {
      dirContext = getDirContext(connInfo);
      
      SearchControls searchControls = new SearchControls();
      searchControls.setSearchScope(searchScope);
      searchControls.setCountLimit(countLimit);
      if (attrs != null) {
        searchControls.setReturningAttributes(attrs);
      }
      results = dirContext.search(searchBase, filter, searchControls);
    }
    finally
    {
      if (dirContext != null) {
        dirContext.close();
      }
    }
    return results;
  }
  
  public Attributes doLDAPSchemaSearch(ConnectionInfo connInfo, String objectClass)
    throws NamingException
  {
    DirContext dirContext = null;
    Attributes schemaAttrs = null;
    try
    {
      dirContext = getDirContext(connInfo);
      DirContext schemaContext = dirContext.getSchema("");
      DirContext schema = (DirContext)schemaContext.lookup("ClassDefinition/" + objectClass);
      schemaAttrs = schema.getAttributes("");
    }
    finally
    {
      if (dirContext != null) {
        dirContext.close();
      }
    }
    return schemaAttrs;
  }
  
  public ArrayList<String> getLDAPAttributeList(ConnectionInfo connInfo)
    throws NamingException
  {
    ArrayList<String> attrs = new ArrayList();
    
    DirContext dirContext = null;
    try
    {
      dirContext = getDirContext(connInfo);
      
      DirContext schemaContext = dirContext.getSchema("");
      DirContext attrDef = (DirContext)schemaContext.lookup("AttributeDefinition");
      NamingEnumeration ne = attrDef.list("");
      while (ne.hasMore()) {
        attrs.add(((NameClassPair)ne.next()).getName());
      }
    }
    finally
    {
      if (dirContext != null) {
        dirContext.close();
      }
    }
    return attrs;
  }
  
  public ArrayList<String> getObjectClasses(ConnectionInfo connInfo, String entryName)
    throws NamingException
  {
    ArrayList<String> objClassNames = new ArrayList();
    DirContext dirContext = null;
    try
    {
      dirContext = getDirContext(connInfo);
      DirContext relatedClasses = dirContext.getSchemaClassDefinition(entryName);
      

      NamingEnumeration nameEnum = relatedClasses.search("", null);
      while (nameEnum.hasMore()) {
        objClassNames.add(((NameClassPair)nameEnum.next()).getName());
      }
    }
    finally
    {
      if (dirContext != null) {
        dirContext.close();
      }
    }
    return objClassNames;
  }
  
  public void modifyAttributes(ConnectionInfo connInfo, Name dirName, Attributes attributes, int modificationCode)
    throws NamingException
  {
    DirContext dirContext = null;
    try
    {
      dirContext = getDirContext(connInfo);
      dirContext.modifyAttributes(dirName, modificationCode, attributes);
    }
    finally
    {
      if (dirContext != null) {
        dirContext.close();
      }
    }
  }
  
  public ArrayList<String> getAllObjectClasses(ConnectionInfo connInfo)
    throws NamingException
  {
    ArrayList<String> attrs = new ArrayList();
    DirContext dirContext = null;
    try
    {
      dirContext = getDirContext(connInfo);
      DirContext schemaContext = dirContext.getSchema("");
      DirContext attrDef = (DirContext)schemaContext.lookup("ClassDefinition");
      NamingEnumeration nameEnum = attrDef.list("");
      while (nameEnum.hasMore()) {
        attrs.add(((NameClassPair)nameEnum.next()).getName());
      }
    }
    finally
    {
      if (dirContext != null) {
        dirContext.close();
      }
    }
    return attrs;
  }
  
  private static DirContext getDirContext(ConnectionInfo connInfo)
    throws NamingException
  {
    Properties env = new Properties();
    
    env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
    env.put("com.sun.jndi.ldap.connect.pool", "true");
    env.put("java.naming.provider.url", connInfo.getServerUrl());
    

    env.put("java.naming.security.authentication", connInfo.getAuthenticationMethod());
    if (connInfo.getPrincipal() != null) {
      env.put("java.naming.security.principal", connInfo.getPrincipal());
    }
    if (connInfo.getCredentials() != null) {
      env.put("java.naming.security.credentials", connInfo.getCredentials());
    }
    DirContext dirContext = new InitialDirContext(env);
    return dirContext;
  }
  
  public static class ConnectionInfo
  {
    private String serverUrl;
    private String authenticationMethod;
    private String principal;
    private String credentials;
    
    public ConnectionInfo(String serverUrl, String authenticationMethod, String principal, String credentials)
    {
      this.serverUrl = serverUrl;
      this.authenticationMethod = authenticationMethod;
      this.principal = principal;
      this.credentials = credentials;
    }
    
    public String getServerUrl()
    {
      return this.serverUrl;
    }
    
    public String getAuthenticationMethod()
    {
      return this.authenticationMethod;
    }
    
    public String getPrincipal()
    {
      return this.principal;
    }
    
    public String getCredentials()
    {
      return this.credentials;
    }
  }
}
