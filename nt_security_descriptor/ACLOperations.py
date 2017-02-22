import struct
import ACEOperations

"""Integer representations of ACL and ACE type constants"""
ACL_TYPE_DACL = 0
ACL_TYPE_SACL = 1

def getACEIndex(aclBytes,aceBytes):
	"""
	Returns the index of the provided ACE bytes within the provided ACL or -1 if it is not present in the ACL.
	"""
	lstAces = getACEList(aclBytes)
	if aceBytes in lstAces:
		return lstAces.index(aceBytes)
	else:
		return -1

def getInfoForACEs(aclBytes):
	"""
	Return a tuple of ACE info lists for the provided ACL which describe the contents of each of the ACEs within the ACL.
	"""
	return tuple([ ACEOperations.aceInfo(aceBytes) for aceBytes in getACEList(aclBytes) ])
	
def getACECount(aclBytes):
	"""
	Returns the number of ACEs present in the given ACL
	"""
	return struct.unpack("<H",aclBytes[4:6])[0]

def getACEList(aclBytes):
	"""
	Returns a list of aceBytes for each ACE in the provided ACL
	"""
	
	lstACEs = []
	currentACEOffset=8
	while currentACEOffset < (len(aclBytes)):
		aceLength = struct.unpack("<H",aclBytes[currentACEOffset+2:currentACEOffset+4])[0]
		lstACEs.append(aclBytes[currentACEOffset:currentACEOffset+aceLength])
		currentACEOffset += aceLength
	return lstACEs

def getACEPositionsList(aclBytes):
	"""
	Returns a list of offsets and lengths for the ACEs in the provided ACL
	"""
	
	lstACEPositions = []
	currentACEOffset=8
	while currentACEOffset < (len(aclBytes)):
		aceLength = struct.unpack("<H",aclBytes[currentACEOffset+2:currentACEOffset+4])[0]
		lstACEPositions.append((currentACEOffset,aceLength))
		currentACEOffset += aceLength
	return lstACEPositions

def createNewACL(aceBytes,isDirectoryServicesACL):
	"""
	Creates a new ACL from scratch with the provided ACE in bytestring format.
	This function assumes that the provided aceBytes are in the correct format.
	Exactly one correctly formatted ACE must be provided for the creation process.
	If the ACE is not formatted correctly, is missing, or more than one ACE is defined
	in the bytestring, unpredictable results may occur.
	"""
	#build a header for the new ACL
	if isDirectoryServicesACL:
		aclRevisionByte="\x04"
	else:
		aclRevisionByte="\x02"
	aclSbz1Byte="\x00"
	aclAclSizeBytes=struct.pack("<H",8+len(aceBytes))
	aclAceCountBytes="\x01\x00"
	aclSbz2Bytes="\x00\x00"
	return aclRevisionByte+aclSbz1Byte+aclAclSizeBytes+aclAceCountBytes+aclSbz2Bytes+aceBytes

def addACEtoACL(aclBytes,aceBytes):
	"""
	Given an ACL, an ACE to add to it and whether or not the ACL belongs to a directory services descriptor,
	Inserts the ACE at the appropriate index in the ACL and returns the modified ACL.
	
	If the ACL provided is empty, this function assumes that a new one must be created.  This is where
	'isDirectoryServicesACL' comes in.
	"""
	
	iAceRank = ACEOperations.aceRank(aceBytes)
	bAceIsInheritable = ACEOperations.aceIsInheritable(aceBytes)
	bAceIsInherited = ACEOperations.aceIsInherited(aceBytes)
	
	#make sure the ACL revision is updated to 0x4 if the ace being added is of the following types.
	if ACEOperations.getACEType(aceBytes) in (ACEOperations.ACE_TYPE_ACCESS_ALLOWED_OBJECT, \
											   ACEOperations.ACE_TYPE_ACCESS_DENIED_OBJECT, \
											   ACEOperations.ACE_TYPE_SYSTEM_AUDIT_OBJECT, \
											   ACEOperations.ACE_TYPE_SYSTEM_ALARM_OBJECT, \
											   ACEOperations.ACE_TYPE_SYSTEM_MANDATORY_LABEL):
		aclRevisionByte='\x04'
	else:
		aclRevisionByte='\x02'
	
	#make sure the ACE to be added is not inheritable or inherited... since this feature is not implemented yet.
	if (bAceIsInheritable or bAceIsInherited):
		raise Exception("Insertion of inherited or inheritable ACEs is not currently supported.")
	
	#Verify the ACL exists. If not, a new header needs to be created from scratch
	if len(aclBytes) > 0:
		
		#get the index of the insertion point for the new ace by comparing rank against exising ACEs
		lstCurrentAclAces = getACEList(aclBytes)
		lstAceRanks=[ACEOperations.aceRank(ace) for ace in lstCurrentAclAces]
		iInsertionIndex=-1
		for i in range(len(lstAceRanks)):
			if iAceRank >= lstAceRanks[i]:
				iInsertionIndex = i
				break	
		if iInsertionIndex == -1:
			iInsertionIndex = len(lstAceRanks)-1
			
		#create a list of aceBytes from the existing aces, then insert the new ace at the insertion index
		lstCurrentAclAces.insert(iInsertionIndex,aceBytes)
		
		#update the AceCount and AclSize in the ACL header
		aclSbz1Byte=aclBytes[1]
		aclAclSizeBytes=aclBytes[2:4]
		aclAceCountBytes=aclBytes[4:6]
		aclSbz2Bytes=aclBytes[6:8]
		iAclSize = struct.unpack("<H",aclAclSizeBytes)[0]
		iAclSize = iAclSize + len(aceBytes)
		aclAclSizeBytes = struct.pack("<H",iAclSize)
		iAceCount = struct.unpack("<H",aclAceCountBytes)[0]
		iAceCount += 1
		aclAceCountBytes = struct.pack("<H",iAceCount)
	else:
		raise Exception("The ACL provided was empty.  Use createNewACL(ace,isDirectoryServicesACL) to create a new ACL instead.")
	#replace the updated ACL bytes in the security descriptor
	newAclHeaderBytes = aclRevisionByte + \
						aclSbz1Byte + \
						aclAclSizeBytes + \
						aclAceCountBytes + \
						aclSbz2Bytes
	lstCurrentAclAces.insert(0,newAclHeaderBytes)	
	newAclBytes = ''.join(lstCurrentAclAces)
	return newAclBytes
		
def removeACEfromACL(aclBytes,aceIndex):
	"""
	Given the ACL and index of the ACE to remove, drop the ACE from the ACL.  If the ACL is empty, remove it as well.
	Returns the resulting ACL bytestring, or an empty string if the ACL is to be removed.
	"""
	#TODO: Test
	currentAclAceCount = getACECount(aclBytes)
	if currentAclAceCount <= aceIndex:
		raise Exception("The ACE index provided is out of range for the ACL provided.")
	elif currentAclAceCount == 1:
		return ""
	
	lstAcePositions = getACEPositionsList(aclBytes)
	
	aclRevisionByte=aclBytes[0]
	aclSbz1Byte=aclBytes[1]
	aclSizeBytes=aclBytes[2:4]
	aclAceCountBytes=aclBytes[4:6]
	aclSbz2Bytes=aclBytes[6:8]
	aclBytesBeforeACE=aclBytes[8:lstAcePositions[aceIndex][0]]
	aclBytesAfterACE=aclBytes[lstAcePositions[aceIndex][0]+lstAcePositions[aceIndex][1]:]
	
	iAclAceCount = struct.unpack("<H",aclAceCountBytes)[0] - 1
	aclAceCountBytes = struct.pack("<H",iAclAceCount)

	iAclSize = struct.unpack("<H",aclSizeBytes)[0] - lstAcePositions[aceIndex][1]
	aclSizeBytes = struct.pack("<H",iAclSize)
	
	newACLBytes = aclRevisionByte + aclSbz1Byte + aclSizeBytes + aclAceCountBytes + aclSbz2Bytes + aclBytesBeforeACE + aclBytesAfterACE
	
	return newACLBytes
