def replaceObjectAttributes(self,strReadableGUID,dictReplacementAttributeValues):
	"""
	Forcefully replaces an object's attribute values with with the attribute values matching those in the provided dictionary
	If the object does not already have a value for any of the provided attributes, this function may error out.
	"""
	LDAP_REPLACE = 2
	modlist=[]
	for key in dictReplacementAttributeValues.keys():
		modlist.append((LDAP_REPLACE,key,dictReplacementAttributeValues[key]))
	try:
		self.lConn.modify_s(self.getDNForObjectGUID(strReadableGUID),modlist)
		return "Attributes for AD object with objectGUID: " + strReadableGUID + " were modified successfully."
	except ldap.LDAPError as e:
		raise ADException("An AD entry with objectGuid: " + strReadableGUID + " could not be modified, reason: " + str(e))
