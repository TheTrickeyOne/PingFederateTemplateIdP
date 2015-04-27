package com.template.adapter.idp.util;

import com.pingidentity.access.DataSourceAccessor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

import org.apache.commons.validator.ValidatorException;
import org.apache.log4j.Logger;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.FieldList;
import org.sourceid.saml20.domain.datasource.info.LdapInfo;
import org.springframework.ldap.core.LdapEncoder;

public class LdapAttributeFinder
{
  private Logger log;
  private String ldapDataSourceAlias;
  private String baseDomain;
  private String ldapFilter;
  private String fnameAttribute;
  private String lnameAttribute;
  private String emailAttribute;
  private NameValidator nameValidator;
  private EmailValidator emailValidator;
  private DataSourceAccessor ldapDataSourceAccessor;
  private LDAPUtil ldapUtil;
  
  public LdapAttributeFinder(Logger log, Configuration configuration, NameValidator nameValidator, EmailValidator emailvalidator, DataSourceAccessor ldapDataSourceAccessor, LDAPUtil ldapUtil)
  {
    this.log = log;
    this.ldapDataSourceAlias = configuration.getAdvancedFields().getFieldValue("LDAP Data source");
    this.baseDomain = configuration.getAdvancedFields().getFieldValue("Base Domain");
    this.ldapFilter = configuration.getAdvancedFields().getFieldValue("Filter");
    this.fnameAttribute = configuration.getAdvancedFields().getFieldValue("fname attribute");
    this.lnameAttribute = configuration.getAdvancedFields().getFieldValue("lname attribute");
    this.emailAttribute = configuration.getAdvancedFields().getFieldValue("email attribute");
    this.nameValidator = nameValidator;
    this.emailValidator = emailvalidator;
    this.ldapDataSourceAccessor = ldapDataSourceAccessor;
    this.ldapUtil = ldapUtil;
  }
  
  public Attributes getUsersAttributes(String username, int ldapSearchScope, int ldapCountLimit)
    throws LdapLookupException
  {
    String email = null;
    
    Attributes ldapResultAttributes = null;
    try
    {
      ldapResultAttributes = getLdapAttributesForUser(username, ldapSearchScope, ldapCountLimit);
      if (ldapResultAttributes != null)
      {
        email = ldapResultAttributes.get(this.emailAttribute) == null ? null : (String)ldapResultAttributes.get(this.emailAttribute).get();
      }
      else
      {
        throw new LdapLookupException("No results found for search.");
      }
    }
    catch (NamingException e)
    {
      throw new LdapLookupException("Error retrieving attributes from LDAP: " + e.getMessage(), e);
    }
    this.log.debug("LDAP Search results for user: " + username + ": {email = " + email + "}");
        
    return ldapResultAttributes;
  }
    
  private Attributes getLdapAttributesForUser(String username, int ldapSearchScope, int ldapCountLimit)
    throws NamingException
  {
    LdapInfo ldapInfo = this.ldapDataSourceAccessor.getLdapInfo(this.ldapDataSourceAlias);
    
    LDAPUtil.ConnectionInfo connectionInfo = new LDAPUtil.ConnectionInfo(ldapInfo.getServerUrl(), ldapInfo.getAuthenticationMethod(), ldapInfo.getPrincipal(), ldapInfo.getCredentials());
    

    String[] attributeArray = { this.fnameAttribute, this.lnameAttribute, this.emailAttribute };
    
    NamingEnumeration<SearchResult> ldapResults = null;
    Attributes ldapResultAttributes = null;
    
    String escapedUsername = LdapEncoder.filterEncode(username);
    
    String parsedFilter = this.ldapFilter.replace("${username}", escapedUsername);
    
    this.log.debug("\nLDAP Search:\n\tURL: " + connectionInfo.getServerUrl() + "\n\tBase Domain: " + this.baseDomain + "\n\tFilter: " + parsedFilter + "\n\tAttributes: " + Arrays.toString(attributeArray) + "\n\tScope: " + ldapSearchScope + "\n\tCount Limit: " + ldapCountLimit);
    
    ldapResults = this.ldapUtil.doLDAPSearch(connectionInfo, this.baseDomain, parsedFilter, ldapSearchScope, attributeArray, ldapCountLimit);
    if (ldapResults.hasMore())
    {
      SearchResult searchResult = (SearchResult)ldapResults.next();
      ldapResultAttributes = searchResult.getAttributes();
      if (ldapResults.hasMore()) {
        throw new NamingException("More than one LDAP search result returned.");
      }
    }
    return ldapResultAttributes;
  }
}
