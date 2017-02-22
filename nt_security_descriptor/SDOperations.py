import struct
import ACLOperations

#Security Descriptor Control Flags
SD_CONTROL_SELF_RELATIVE=32768
SD_CONTROL_RM_CONTROL_VALID=16384
SD_CONTROL_SACL_PROTECTED=8192
SD_CONTROL_DACL_PROTECTED=4096
SD_CONTROL_SACL_AUTOINHERITED=2048
SD_CONTROL_DACL_AUTOINHERITED=1024
SD_CONTROL_SACL_COMPUTED_INHERITANCE_REQD=512
SD_CONTROL_DACL_COMPUTED_INHERITANCE_REQD=256
SD_CONTROL_DACL_TRUSTED=128
SD_CONTROL_SERVER_SECURITY=64
SD_CONTROL_SACL_DEFAULTED=32
SD_CONTROL_SACL_PRESENT=16
SD_CONTROL_DACL_DEFAULTED=8
SD_CONTROL_DACL_PRESENT=4
SD_CONTROL_GROUP_DEFAULTED=2
SD_CONTROL_OWNER_DEFAULTED=1


def getOwnerOffset(sdBytes):
	"""
	Returns the offset, in bytes (as an integer), of the owner SID in the security descriptor
	"""
	return struct.unpack("<I",sdBytes[4:8])[0]

def getOwnerSIDBytes(sdBytes):
	"""
	Returns the SID bytestring for the owner on the security descriptor
	"""
	#get sid subauthority count to determine size of the sid in bytes
	#sid size = 8 bytes for header + 4 bytes*number of sub authorities
	
	ownerOffset = getOwnerOffset(sdBytes)
	subauthcount=struct.unpack("<B",sdBytes[ownerOffset+1])[0]
	return sdBytes[ownerOffset:ownerOffset+8+(subauthcount*4)]

def getGroupOffset(sdBytes):
	"""
	Returns the offset, in bytes (as an integer), of the owner SID in the security descriptor
	"""
	return struct.unpack("<I",sdBytes[8:12])[0]

def getGroupSIDBytes(sdBytes):
	"""
	Returns the SID bytestring for the owner on the security descriptor
	"""
	#get sid subauthority count to determine size of the sid in bytes
	#sid size = 8 bytes for header + 4 bytes*number of sub authorities
	
	groupOffset = getGroupOffset(sdBytes)
	subauthcount=struct.unpack("<B",sdBytes[groupOffset+1])[0]
	return sdBytes[groupOffset:groupOffset+8+(subauthcount*4)]

def aclBytes(sdBytes,aclType):
	"""
	Returns a bytestring representation of the ACL of the type specified contained within the provided security descriptor
	"""
	if aclType==ACLOperations.ACL_TYPE_SACL:
		offset=struct.unpack("<I",sdBytes[12:16])[0]
	elif aclType==ACLOperations.ACL_TYPE_DACL:
		offset=struct.unpack("<I",sdBytes[16:20])[0]
	else:
		raise Exception("Invalid ACL type specified.")
	if offset==0:
		return "" #the requested ACL does not exist in this security descriptor.  Return an empty string.
	else:
		size=struct.unpack("<H",sdBytes[offset+2:offset+4])[0]
		return sdBytes[offset:offset+size]

def getControlFlags(sdBytes):
	"""
	Return an integer representation of the control flags for the provided security descriptor
	"""
	return struct.unpack("<H",sdBytes[2:4])[0]

def readableControlFlags(cflags):
	"""
	Return a list of readable control flags given an integer representation of the control flags.
	"""
	cflags = self.getControlFlags()
	lstflags = []
	if cflags & SD_CONTROL_SELF_RELATIVE == SD_CONTROL_SELF_RELATIVE:
		lstflags.append("SD_CONTROL_SELF_RELATIVE")
	if cflags & SD_CONTROL_RM_CONTROL_VALID == SD_CONTROL_RM_CONTROL_VALID:
		lstflags.append("SD_CONTROL_RM_CONTROL_VALID")
	if cflags & SD_CONTROL_SACL_PROTECTED == SD_CONTROL_SACL_PROTECTED:
		lstflags.append("SD_CONTROL_SACL_PROTECTED")
	if cflags & SD_CONTROL_DACL_PROTECTED == SD_CONTROL_DACL_PROTECTED:
		lstflags.append("SD_CONTROL_DACL_PROTECTED")
	if cflags & SD_CONTROL_SACL_AUTOINHERITED == SD_CONTROL_SACL_AUTOINHERITED:
		lstflags.append("SD_CONTROL_SACL_AUTOINHERITED")
	if cflags & SD_CONTROL_DACL_AUTOINHERITED == SD_CONTROL_DACL_AUTOINHERITED:
		lstflags.append("SD_CONTROL_DACL_AUTOINHERITED")
	if cflags & SD_CONTROL_SACL_COMPUTED_INHERITANCE_REQD == SD_CONTROL_SACL_COMPUTED_INHERITANCE_REQD:
		lstflags.append("SD_CONTROL_SACL_COMPUTED_INHERITANCE_REQD")
	if cflags & SD_CONTROL_DACL_COMPUTED_INHERITANCE_REQD == SD_CONTROL_DACL_COMPUTED_INHERITANCE_REQD:
		lstflags.append("SD_CONTROL_DACL_COMPUTED_INHERITANCE_REQD")
	if cflags & SD_CONTROL_DACL_TRUSTED == SD_CONTROL_DACL_TRUSTED:
		lstflags.append("SD_CONTROL_DACL_TRUSTED")
	if cflags & SD_CONTROL_SERVER_SECURITY == SD_CONTROL_SERVER_SECURITY:
		lstflags.append("SD_CONTROL_SERVER_SECURITY")
	if cflags & SD_CONTROL_SACL_DEFAULTED == SD_CONTROL_SACL_DEFAULTED:
		lstflags.append("SD_CONTROL_SACL_DEFAULTED")
	if cflags & SD_CONTROL_SACL_PRESENT == SD_CONTROL_SACL_PRESENT:
		lstflags.append("SD_CONTROL_SACL_PRESENT")
	if cflags & SD_CONTROL_DACL_DEFAULTED == SD_CONTROL_DACL_DEFAULTED:
		lstflags.append("SD_CONTROL_DACL_DEFAULTED")
	if cflags & SD_CONTROL_DACL_PRESENT == SD_CONTROL_DACL_PRESENT:
		lstflags.append("SD_CONTROL_DACL_PRESENT")
	if cflags & SD_CONTROL_GROUP_DEFAULTED == SD_CONTROL_GROUP_DEFAULTED:
		lstflags.append("SD_CONTROL_GROUP_DEFAULTED")
	if cflags & SD_CONTROL_OWNER_DEFAULTED == SD_CONTROL_OWNER_DEFAULTED:
		lstflags.append("SD_CONTROL_OWNER_DEFAULTED")
	return lstflags
		
def replaceACL(sdBytes,aclType,newACLBytes):
	"""
	TODO: Given the ACL to replace, and a new set of bytes representing what the ACL should look like, replace the existing 
	ACL in the provided security descriptor.
	This method does not perform any checks to see if the bytes provided are valid, so caution should be taken when invoking this.
	"""
	lstNewSD=[ \
			  sdBytes[0], \
			  sdBytes[1], \
			  sdBytes[2:4], \
			  sdBytes[4:8], \
			  sdBytes[8:12], \
			  sdBytes[12:16], \
			  sdBytes[16:20] \
			 ]
	
	IDX_REVISION_BYTE=0
	IDX_SBZ1_BYTE=1
	IDX_CONTROL_BYTES=2
	IDX_OWNER_OFFSET_BYTES=3
	IDX_GROUP_OFFSET_BYTES=4
	IDX_SACL_OFFSET_BYTES=5
	IDX_DACL_OFFSET_BYTES=6
	
	#We can't be sure what order the ACLs and SIDs are currently in..
	#Also not entirely sure if it matters...
	#To be safe, we're taking this into account and putting the ACLs and SIDs back in the same order they were originally in...
	iOwnerOffset = struct.unpack("<I",lstNewSD[IDX_OWNER_OFFSET_BYTES])[0]
	iGroupOffset = struct.unpack("<I",lstNewSD[IDX_GROUP_OFFSET_BYTES])[0]
	iSACLOffset = struct.unpack("<I",lstNewSD[IDX_SACL_OFFSET_BYTES])[0]
	iDACLOffset = struct.unpack("<I",lstNewSD[IDX_DACL_OFFSET_BYTES])[0]
	lstSorted = sorted([iOwnerOffset,iGroupOffset,iSACLOffset,iDACLOffset])
	
	for itm in lstSorted:
		newObjectIndex = len(lstNewSD)
		if itm == iOwnerOffset:
			IDX_OWNER_BYTES=newObjectIndex
			lstNewSD.append(getOwnerSIDBytes(sdBytes))
		elif itm == iGroupOffset:
			IDX_GROUP_BYTES=newObjectIndex
			lstNewSD.append(getGroupSIDBytes(sdBytes))
		elif itm == iSACLOffset:
			IDX_SACL_BYTES=newObjectIndex
			lstNewSD.append(aclBytes(sdBytes,ACLOperations.ACL_TYPE_SACL))
		elif itm == iDACLOffset:
			IDX_DACL_BYTES=newObjectIndex
			lstNewSD.append(aclBytes(sdBytes,ACLOperations.ACL_TYPE_DACL))
	
	iCurrentSDControlFlags=struct.unpack("<H",lstNewSD[IDX_CONTROL_BYTES])[0]
	
	if aclType == ACLOperations.ACL_TYPE_SACL:
		#set the control bytes appropriately for the new SACL 
		if len(newACLBytes) == 0: #we're getting rid of the SACL
			if iCurrentSDControlFlags & SD_CONTROL_SACL_PRESENT == SD_CONTROL_SACL_PRESENT:
				iNewSDControlFlags = iCurrentSDControlFlags - SD_CONTROL_SACL_PRESENT
			else:
				iNewSDControlFlags = iCurrentSDControlFlags
				lstNewSD[IDX_CONTROL_BYTES]=struct.pack("<H",iNewSDControlFlags)
				sdOffsetSACLBytes=struct.pack("<I",0) #offset bytes for SACL are zeroed out when SACL is not present
		else: #ACL should be marked present
			if iCurrentSDControlFlags & SD_CONTROL_SACL_PRESENT == SD_CONTROL_SACL_PRESENT:
				iNewSDControlFlags = iCurrentSDControlFlags
			else:
				iNewSDControlFlags = iCurrentSDControlFlags + SD_CONTROL_SACL_PRESENT
				lstNewSD[IDX_CONTROL_BYTES]=struct.pack("<H",iNewSDControlFlags)
		lstNewSD[IDX_SACL_BYTES]=newACLBytes	
	elif aclType == ACLOperations.ACL_TYPE_DACL:
		#set the control bytes appropriately for the new DACL
		if len(newACLBytes) == 0: #Getting rid of DACL
			if iCurrentSDControlFlags & SD_CONTROL_DACL_PRESENT == SD_CONTROL_DACL_PRESENT:
				iNewSDControlFlags = iCurrentSDControlFlags - SD_CONTROL_SACL_PRESENT
			else:
				iNewSDControlFlags = iCurrentSDControlFlags
			sdControlBytes=struct.pack("<H",iNewSDControlFlags)
			sdOffsetDACLBytes=struct.pack("<I",0) #offset bytes for DACL are zeroed out when DACL is not present
		else: #DACL should be marked present
			if iCurrentSDControlFlags & SD_CONTROL_DACL_PRESENT == SD_CONTROL_DACL_PRESENT:
				iNewSDControlFlags = iCurrentSDControlFlags
			else:
				iNewSDControlFlags = iCurrentSDControlFlags + SD_CONTROL_DACL_PRESENT
			sdControlBytes=struct.pack("<H",iNewSDControlFlags)
		lstNewSD[IDX_DACL_BYTES]=newACLBytes
	else:
		raise Exception("Invalid ACL type specified.")
	
	#update the offsets in the new security descriptor appropriately
	iByteCount=0
	for i in range(IDX_OWNER_BYTES):
		iByteCount+=len(lstNewSD[i])
	lstNewSD[IDX_OWNER_OFFSET_BYTES]=struct.pack("<I",iByteCount)
	iByteCount=0
	for i in range(IDX_GROUP_BYTES):
		iByteCount+=len(lstNewSD[i])
	lstNewSD[IDX_GROUP_OFFSET_BYTES]=struct.pack("<I",iByteCount)
	iByteCount=0
	if len(lstNewSD[IDX_SACL_BYTES]) > 0: #only set the offset bytes if the SACL exists (length greater than 0 bytes)
		for i in range(IDX_SACL_BYTES):
			iByteCount+=len(lstNewSD[i])
		lstNewSD[IDX_SACL_OFFSET_BYTES]=struct.pack("<I",iByteCount)
	iByteCount=0
	if len(lstNewSD[IDX_DACL_BYTES]) > 0: #only set the offset bytes if the DACL exists (length greater than 0 bytes)
		for i in range(IDX_DACL_BYTES):
			iByteCount+=len(lstNewSD[i])
		lstNewSD[IDX_DACL_OFFSET_BYTES]=struct.pack("<I",iByteCount)
	
	#return the newly updated security descriptor
	return ''.join(lstNewSD)
