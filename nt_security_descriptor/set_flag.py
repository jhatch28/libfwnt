def setUserCannotChangePasswordFlag(self,strReadableGUID,userCannotChangePassword):
    """
    If setting the flag to on,
    SecurityDescriptorOperations is called on the nTSecurityDescriptor attribute of the user with the provided objectGUID.
    If deny ACEs for changing password already exist, nothing is done... else,
    ACEOperations is called to generate the appropriate ACEs which deny the user rights to change their password. 
    Then SecurityDescriptorOperations is called again to modify the nTSecurityDescriptor of the user account associated
    with the provided objectGUID. The deny ACEs are added to the security descriptor, then the user's old security descriptor
    is overwritten with the new one.
    
    If setting the flag to off, SecurityDescriptorOperations is used to check for and remove the deny ACEs if necessary.
    """
            
    #Get the SID and security descriptor for the user with provided guid
    dictUserAttrs = self.getAttributesForObjectGUID(strReadableGUID,['objectSid','nTSecurityDescriptor','objectClass'])
    if len(dictUserAttrs) == 0:
        raise ADException("Account with objectGUID: " + strReadableGUID + " was not found.")
    userObjectClasses = dictUserAttrs['objectClass']
    if 'user' not in [i.lower() for i in userObjectClasses]:
        raise ADException("The provided objectGUID does not represent a user account.")
    userSecurityDescriptorBytes = dictUserAttrs['nTSecurityDescriptor'][0]
    if len(userSecurityDescriptorBytes) == 0:
        raise ADException("Active Directory returned an empty nTSecurityDescriptor for the provided user account. This is usually because the service account used to query LDAP does not have domain admin privileges.")
    userSIDBytes = dictUserAttrs['objectSid'][0]
            
    #Define the deny 'Everyone' and 'Self' password change ACEs as assigned by AD when checking 'user cannot change password'
    denyEveryoneAceBytes = ACEOperations.constructObjectACE(ACEOperations.ACE_TYPE_ACCESS_DENIED_OBJECT,0, \
                                                                    ACEOperations.ADS_RIGHT_DS_CONTROL_ACCESS, \
                                                                    SIDOperations.readableSIDAsBytes("S-1-1-0"), \
                                                                    ACEOperations.EXT_RIGHT_USER_CHANGE_PASSWORD)
    denySelfAceBytes = ACEOperations.constructObjectACE(ACEOperations.ACE_TYPE_ACCESS_DENIED_OBJECT,0, \
                                                                    ACEOperations.ADS_RIGHT_DS_CONTROL_ACCESS, \
                                                                    SIDOperations.readableSIDAsBytes("S-1-5-10"), \
                                                                    ACEOperations.EXT_RIGHT_USER_CHANGE_PASSWORD)
    
    #Define the Allow 'Everyone' password change ACE as assigned by AD when unchecking 'user cannot change password'
    allowEveryoneAceBytes = ACEOperations.constructObjectACE(ACEOperations.ACE_TYPE_ACCESS_ALLOWED_OBJECT,0, \
                                                             ACEOperations.ADS_RIGHT_DS_CONTROL_ACCESS, \
                                                             SIDOperations.readableSIDAsBytes("S-1-1-0"), \
                                                             ACEOperations.EXT_RIGHT_USER_CHANGE_PASSWORD)

    #grab the DACL from the user's security descriptor
    daclBytes = SDOperations.aclBytes(userSecurityDescriptorBytes,ACLOperations.ACL_TYPE_DACL)

    sdChangeFlag=False
    if userCannotChangePassword:
        #remove the allow 'Everyone' ACE if it does exist
        idx_allowEveryoneAce = ACLOperations.getACEIndex(daclBytes,allowEveryoneAceBytes)
        if idx_allowEveryoneAce <> -1:
            daclBytes = ACLOperations.removeACEfromACL(daclBytes,idx_allowEveryoneAce)
            sdChangeFlag=True
        #add the deny 'Everyone' and 'Self' ACEs if they do not exist
        if ACLOperations.getACEIndex(daclBytes,denyEveryoneAceBytes) == -1:
            daclBytes = ACLOperations.addACEtoACL(daclBytes,denyEveryoneAceBytes)
            sdChangeFlag=True
        if ACLOperations.getACEIndex(daclBytes,denySelfAceBytes) == -1:
            daclBytes = ACLOperations.addACEtoACL(daclBytes,denySelfAceBytes)
            sdChangeFlag=True
    else:
        #remove the deny 'Everyone' and 'Self' ACEs if they do exist
        idx_denyEveryoneAce = ACLOperations.getACEIndex(daclBytes,denyEveryoneAceBytes)
        if idx_denyEveryoneAce <> -1:
            daclBytes = ACLOperations.removeACEfromACL(daclBytes,idx_denyEveryoneAce)
            sdChangeFlag=True
        idx_denySelfAce = ACLOperations.getACEIndex(daclBytes,denySelfAceBytes)
        if idx_denySelfAce <> -1:
            daclBytes = ACLOperations.removeACEfromACL(daclBytes,idx_denySelfAce)
            sdChangeFlag=True
        #add the allow 'Everyone' change password ACE if it does not exist
        #I am mimicking what AD does when unchecking 'user cannot change password'.  
        #Not sure why they allow 'Everyone' and not just 'Self' and 'Account Operators' or similar,
        #but this is what Microsoft does, so...
        #Note that if you do not add an allow ace after removing the deny ace, permissions default to deny
        #which is why allow needs to be explicitly define afterwards.
        idx_allowEveryoneAce = ACLOperations.getACEIndex(daclBytes,allowEveryoneAceBytes)
        if idx_allowEveryoneAce == -1:
            daclBytes = ACLOperations.addACEtoACL(daclBytes,allowEveryoneAceBytes)
            sdChangeFlag=True

    if sdChangeFlag:
        userSecurityDescriptorBytes = SDOperations.replaceACL(userSecurityDescriptorBytes,ACLOperations.ACL_TYPE_DACL,daclBytes)
        return self.replaceObjectAttributes(strReadableGUID,{'nTSecurityDescriptor':userSecurityDescriptorBytes})
