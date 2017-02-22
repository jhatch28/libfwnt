import SIDOperations
import struct
import uuid
	
""" ACE structure Integer Constants """
#ACE Types
ACE_TYPE_ACCESS_ALLOWED = 0
ACE_TYPE_ACCESS_DENIED = 1
ACE_TYPE_SYSTEM_AUDIT = 2
ACE_TYPE_SYSTEM_ALARM = 3
ACE_TYPE_ACCESS_ALLOWED_COMPOUND = 4
ACE_TYPE_ACCESS_ALLOWED_OBJECT = 5
ACE_TYPE_ACCESS_DENIED_OBJECT = 6
ACE_TYPE_SYSTEM_AUDIT_OBJECT = 7
ACE_TYPE_SYSTEM_ALARM_OBJECT = 8
ACE_TYPE_ACCESS_ALLOWED_CALLBACK = 9
ACE_TYPE_ACCESS_DENIED_CALLBACK = 10
ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT = 11
ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT = 12
ACE_TYPE_SYSTEM_AUDIT_CALLBACK = 13
ACE_TYPE_SYSTEM_ALARM_CALLBACK = 14
ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT = 15
ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT = 16
ACE_TYPE_SYSTEM_MANDATORY_LABEL = 17
ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE = 18
ACE_TYPE_SYSTEM_SCOPED_POLICY_ID = 19

#ACE Flags
ACE_FLAG_OBJECT_INHERIT = 1
ACE_FLAG_CONTAINER_INHERIT = 2
ACE_FLAG_NO_PROPAGATE = 4
ACE_FLAG_INHERIT_ONLY = 8
ACE_FLAG_INHERITED = 16
ACE_FLAG_NOTDOCUMENTED = 32
ACE_FLAG_SUCCESSFUL_ACCESS = 64
ACE_FLAG_FAILED_ACCESS = 128

#ACE Generic Mask Values
ACCESS_MASK_GENERIC_READ = 2147483648
ACCESS_MASK_GENERIC_WRITE = 1073741824
ACCESS_MASK_GENERIC_EXECUTE = 536870912
ACCESS_MASK_GENERIC_ALL = 268435456
ACCESS_MASK_MAXIMUM_ALLOWED = 33554432
ACCESS_MASK_ACCESS_SYSTEM_SECURITY = 16777216
ACCESS_MASK_SYNCHRONIZE = 1048576
ACCESS_MASK_WRITE_OWNER = 524288
ACCESS_MASK_WRITE_DACL = 262144
ACCESS_MASK_READ_CONTROL = 131072
ACCESS_MASK_DELETE = 65536

#ACE Object Rights Validity Flags
ACE_OBJECT_TYPE_PRESENT=1
ACE_INHERITED_OBJECT_TYPE_PRESENT=2

#ACE Mask Object Rights
ADS_RIGHT_DS_CREATE_CHILD=1
ADS_RIGHT_DS_DELETE_CHILD=2
ADS_RIGHT_DS_SELF=8
ADS_RIGHT_DS_READ_PROP=16
ADS_RIGHT_DS_WRITE_PROP=32
ADS_RIGHT_DS_CONTROL_ACCESS=256

#Extended Rights Objects
#See http://technet.microsoft.com/en-us/library/ff405676.aspx for additional extended rights objects
EXT_RIGHT_USER_CHANGE_PASSWORD=uuid.UUID('ab721a53-1e2f-11d0-9819-00aa0040529b')



def constructSimpleACE(intAceType,intAceFlags,intMask,trusteeSIDBytes):
	"""
	Constructs and returns a simple access control entry byte structure from the provided information.
	aceType, flags and mask are expected to be in integer format.
	trusteeSID should be passed to this method as a bytestring.
	
	While this function does guarantee correct structuring of objects within the ACE, such as objectSIDs and objectGUIDs, it does not 
	guarantee validity of the objects in the context of the domain (do they represent valid objects in the domain?).
	
	Care should be taken about data provided to the ACE, or the ACL (and therefore the security descriptor) may become corrupted, 
	or grant/deny rights on/to incorrect/invalid objects.
	"""
	
	#check aceType validity
	if intAceType not in (ACE_TYPE_ACCESS_ALLOWED, \
					   ACE_TYPE_ACCESS_DENIED, \
					   ACE_TYPE_SYSTEM_AUDIT, \
					   ACE_TYPE_SYSTEM_MANDATORY_LABEL, \
					   ACE_TYPE_SYSTEM_SCOPED_POLICY_ID):
		raise Exception("The ACE type provided to constructSimpleACE was not valid. Simple ACEs must be constructed from one of the following ACE Types: ACE_TYPE_ACCESS_ALLOWED,ACE_TYPE_ACCESS_DENIED,ACE_TYPE_SYSTEM_AUDIT,ACE_TYPE_SYSTEM_MANDATORY_LABEL,ACE_TYPE_SYSTEM_SCOPED_POLICY_ID")
	#check flags validity
	if intAceFlags not in range(0,256):
		raise Exception("The flags provided to constructSimpleACE were not valid. " \
						+ "ACE flags include one or more of the following flags: " \
						+ "ACE_FLAG_OBJECT_INHERIT = 1, " \
						+ "ACE_FLAG_CONTAINER_INHERIT = 2, " \
						+ "ACE_FLAG_NO_PROPAGATE = 4, " \
						+ "ACE_FLAG_INHERIT_ONLY = 8, " \
						+ "ACE_FLAG_INHERITED = 16, " \
						+ "ACE_FLAG_NOTDOCUMENTED = 32, " \
						+ "ACE_FLAG_SUCCESSFUL_ACCESS = 64 " \
						+ "ACE_FLAG_FAILED_ACCESS = 128 ")
	#check mask validity
	if not (intMask >= 65536 and intMask <= 4078895104):
		raise Exception("The mask provided to constructSimpleACE was not valid. " \
						+ "Simple ACE Masks include one or more of the following flags: " \
						+ "ACCESS_MASK_GENERIC_READ = 2147483648, " \
						+ "ACCESS_MASK_GENERIC_WRITE = 1073741824, " \
						+ "ACCESS_MASK_GENERIC_EXECUTE = 536870912, " \
						+ "ACCESS_MASK_GENERIC_ALL = 268435456, " \
						+ "ACCESS_MASK_MAXIMUM_ALLOWED = 33554432, " \
						+ "ACCESS_MASK_ACCESS_SYSTEM_SECURITY = 16777216, " \
						+ "ACCESS_MASK_SYNCHRONIZE = 1048576, " \
						+ "ACCESS_MASK_WRITE_OWNER = 524288, " \
						+ "ACCESS_MASK_WRITE_DACL = 262144, " \
						+ "ACCESS_MASK_READ_CONTROL = 131072, " \
						+ "ACCESS_MASK_DELETE = 65536")
	#check sid validity
	if not SIDOperations.sidIsValid(trusteeSIDBytes):
		raise Exception("The provided SID is not valid.  See http://msdn.microsoft.com/en-us/library/gg465313.aspx for correct SID structure.")
	
	#Everything checks out - create the ACE
	#aceSize is two bytes and the least multiple of four greater than or equal to the actual size of the entire ACE, which is TBD so we enter
	#zeroes for placeholders for now
	aceHeader = [intAceType,intAceFlags,0,0]
	barray = bytearray(aceHeader)
	
	maskBytes = struct.pack("<I",intMask)
	barray.extend(bytearray(maskBytes))
	barray.extend(bytearray(trusteeSIDBytes))
	aceActualSize = len(str(barray))
	if aceActualSize % 4 <> 0:
		#print "Ace actual size (" + str(aceActualSize) + ") is not a divisor of 4."
		aceByteSize = int(aceActualSize/4)*4+4
		#print "Setting byte size to: " + str(aceByteSize)
	else:
		aceByteSize = aceActualSize
		
	byteSizeBytes = struct.pack("<H",aceByteSize)
	barray[2] = byteSizeBytes[0]
	barray[3] = byteSizeBytes[1]
	return str(barray)

def constructObjectACE(intAceType,intAceFlags,intMask,trusteeSIDBytes,objectTypeUUID=None,inheritedObjectTypeUUID=None):
	"""
	Constructs and returns an object access control entry byte structure from the provided information
	objectTypeGUID and inheritedObjectTypeGUID should be stored as python uuid.UUID.
	Note: care should be taken when constructing the python UUID object to create it with the AD objectGUID bytes specified in 
	little-endian format.
	"""
	
	#check aceType validity
	if intAceType not in (ACE_TYPE_ACCESS_ALLOWED_OBJECT, \
					   ACE_TYPE_ACCESS_DENIED_OBJECT):
		raise Exception("The ACE type provided to constructObjectACE was not valid. " \
						+ "Object ACEs must be constructed from one of the following ACE Types: " \
						+ "ACE_TYPE_ACCESS_ALLOWED_OBJECT,ACE_TYPE_ACCESS_DENIED_OBJECT")

	#check flags validity
	if intAceFlags not in range(0,256):
		raise Exception("The flags provided to constructObjectACE were not valid. " \
						+ "ACE flags include one or more of the following flags: " \
						+ "ACE_FLAG_OBJECT_INHERIT = 1, " \
						+ "ACE_FLAG_CONTAINER_INHERIT = 2, " \
						+ "ACE_FLAG_NO_PROPAGATE = 4, " \
						+ "ACE_FLAG_INHERIT_ONLY = 8, " \
						+ "ACE_FLAG_INHERITED = 16, " \
						+ "ACE_FLAG_NOTDOCUMENTED = 32, " \
						+ "ACE_FLAG_SUCCESSFUL_ACCESS = 64 " \
						+ "ACE_FLAG_FAILED_ACCESS = 128 ")
	#check mask validity
	if intMask not in (ADS_RIGHT_DS_CREATE_CHILD, \
					ADS_RIGHT_DS_DELETE_CHILD, \
					ADS_RIGHT_DS_SELF, \
					ADS_RIGHT_DS_READ_PROP, \
					ADS_RIGHT_DS_WRITE_PROP, \
					ADS_RIGHT_DS_CONTROL_ACCESS):
		raise Exception("The mask provided to constructObjectACE was not valid. " \
						+ "Object ACE Masks include ONE of the following flags: " \
						+ "ADS_RIGHT_DS_CREATE_CHILD=1, "
						+ "ADS_RIGHT_DS_DELETE_CHILD=2, "
						+ "ADS_RIGHT_DS_SELF=8, "
						+ "ADS_RIGHT_DS_READ_PROP=16, "
						+ "ADS_RIGHT_DS_WRITE_PROP=32, "
						+ "ADS_RIGHT_DS_CONTROL_ACCESS=256")

	#check sid validity
	if not SIDOperations.sidIsValid(trusteeSIDBytes):
		raise Exception("The provided SID is not valid.  See http://msdn.microsoft.com/en-us/library/gg465313.aspx for correct SID structure.")
	
	#Everything checks out - create the ACE
	#aceSize is two bytes and the least multiple of four greater than or equal to the actual size of the entire ACE, which is TBD so we enter
	#zeroes for placeholders for now
	aceTypeByte = struct.pack("<B",intAceType)
	aceFlagsByte = struct.pack("<B",intAceFlags)
	aceSizeBytes = struct.pack("<H",0) #2-bytes, TBD after finished building entire ACE
	maskBytes = struct.pack("<I",intMask)

	intObjectFlags = 0
	if objectTypeUUID is not None:
		intObjectFlags+=1
		objectTypeBytes = objectTypeUUID.bytes_le
	else:
		objectTypeBytes = ""
	if inheritedObjectTypeUUID is not None:
		intObjectFlags+=2
		inheritedObjectTypeBytes = inheritedObjectTypeUUID.bytes_le
	else:
		inheritedObjectTypeBytes = ""
	
	objectTypeFlagsBytes = struct.pack("<I",intObjectFlags)

	#Size of the ace depends on whether or not objectType and inheritedObjectType GUIDs are present.
	if intObjectFlags == 0:
		aceActualSize = 12+len(trusteeSIDBytes)
	elif intObjectFlags in (ACE_OBJECT_TYPE_PRESENT,ACE_INHERITED_OBJECT_TYPE_PRESENT):
		aceActualSize = 28+len(trusteeSIDBytes)
	else:	
		aceActualSize = 44+len(trusteeSIDBytes)

	if aceActualSize % 4 <> 0:
		#print "Ace actual size (" + str(aceActualSize) + ") is not a divisor of 4."
		aceByteSize = int(aceActualSize/4)*4+4
		#print "Setting byte size to: " + str(aceByteSize)
	else:
		aceByteSize = aceActualSize
		
	aceSizeBytes = struct.pack("<H",aceByteSize)
	newAceBytes = aceTypeByte+aceFlagsByte+aceSizeBytes+maskBytes+objectTypeFlagsBytes+objectTypeBytes+inheritedObjectTypeBytes+trusteeSIDBytes
	return newAceBytes

def constructAppDataACE(intAceType,intAceFlags,intMask,trusteeSIDBytes,appDataBytes=""):
	"""
	Constructs and returns an AppData access control entry byte structure from the provided information
	"""
	#check aceType validity
	if intAceType not in (ACE_TYPE_ACCESS_ALLOWED_CALLBACK, \
						  ACE_TYPE_ACCESS_DENIED_CALLBACK, \
						  ACE_TYPE_SYSTEM_AUDIT_CALLBACK):
		raise Exception("The ACE type provided to constructAppDataACE was not valid. " \
						+ "AppData ACEs must be constructed from one of the following ACE Types: " \
						+ "ACE_TYPE_ACCESS_ALLOWED_CALLBACK,ACE_TYPE_ACCESS_DENIED_CALLBACK,ACE_TYPE_SYSTEM_AUDIT_CALLBACK")

	#check flags validity
	if intAceFlags not in range(0,256):
		raise Exception("The flags provided to constructAppDataACE were not valid. " \
						+ "ACE flags include one or more of the following flags: " \
						+ "ACE_FLAG_OBJECT_INHERIT = 1, " \
						+ "ACE_FLAG_CONTAINER_INHERIT = 2, " \
						+ "ACE_FLAG_NO_PROPAGATE = 4, " \
						+ "ACE_FLAG_INHERIT_ONLY = 8, " \
						+ "ACE_FLAG_INHERITED = 16, " \
						+ "ACE_FLAG_NOTDOCUMENTED = 32, " \
						+ "ACE_FLAG_SUCCESSFUL_ACCESS = 64 " \
						+ "ACE_FLAG_FAILED_ACCESS = 128 ")
	#check mask validity
	if not (intMask >= 65536 and intMask <= 4078895104):
		raise Exception("The mask provided to constructSimpleACE was not valid. " \
						+ "Simple ACE Masks include one or more of the following flags: " \
						+ "ACCESS_MASK_GENERIC_READ = 2147483648, " \
						+ "ACCESS_MASK_GENERIC_WRITE = 1073741824, " \
						+ "ACCESS_MASK_GENERIC_EXECUTE = 536870912, " \
						+ "ACCESS_MASK_GENERIC_ALL = 268435456, " \
						+ "ACCESS_MASK_MAXIMUM_ALLOWED = 33554432, " \
						+ "ACCESS_MASK_ACCESS_SYSTEM_SECURITY = 16777216, " \
						+ "ACCESS_MASK_SYNCHRONIZE = 1048576, " \
						+ "ACCESS_MASK_WRITE_OWNER = 524288, " \
						+ "ACCESS_MASK_WRITE_DACL = 262144, " \
						+ "ACCESS_MASK_READ_CONTROL = 131072, " \
						+ "ACCESS_MASK_DELETE = 65536")

	#check sid validity
	if not SIDOperations.sidIsValid(trusteeSIDBytes):
		raise Exception("The provided SID is not valid.  See http://msdn.microsoft.com/en-us/library/gg465313.aspx for correct SID structure.")
	
	#Everything checks out - create the ACE
	#aceSize is two bytes and the least multiple of four greater than or equal to the actual size of the entire ACE, which is TBD so we enter
	#zeroes for placeholders for now
	aceTypeByte = struct.pack("<B",intAceType)
	aceFlagsByte = struct.pack("<B",intAceFlags)
	aceSizeBytes = struct.pack("<H",0) #2-bytes, TBD after finished building entire ACE
	maskBytes = struct.pack("<I",intMask)

	aceActualSize = 8 + len(trusteeSIDBytes) + len(appDataBytes)
	if aceActualSize % 4 <> 0:
		#print "Ace actual size (" + str(aceActualSize) + ") is not a divisor of 4."
		aceByteSize = int(aceActualSize/4)*4+4
		#print "Setting byte size to: " + str(aceByteSize)
	else:
		aceByteSize = aceActualSize
		
	aceSizeBytes = struct.pack("<H",aceByteSize)
	newAceBytes = aceTypeByte+aceFlagsByte+aceSizeBytes+maskBytes+trusteeSIDBytes+appDataBytes
	return newAceBytes

def constructObjectAppDataACE(intAceType,intAceFlags,intMask,trusteeSIDBytes,objectTypeUUID=None,inheritedObjectTypeUUID=None,appDataBytes=""):
	"""
	Constructs and returns an object appdata access control entry byte structure from the provided information.
	objectTypeUUID and inheritedObjectTypeUUID should be stored as python uuid.UUID.
	Note: care should be taken when constructing the python UUID object to create it with the AD objectGUID bytes specified in 
	little-endian format.
	"""
	#check aceType validity
	if intAceType not in (ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT, \
					   ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, \
					   ACE_TYPE_SYSTEM_AUDIT_OBJECT, \
					   ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
		raise Exception("The ACE type provided to constructObjectAppDataACE was not valid. " \
						+ "Object ACEs must be constructed from one of the following ACE Types: " \
						+ "ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,ACE_TYPE_SYSTEM_AUDIT_OBJECT,ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT")

	#check flags validity
	if intAceFlags not in range(0,256):
		raise Exception("The flags provided to constructObjectAppDataACE were not valid. " \
						+ "ACE flags include one or more of the following flags: " \
						+ "ACE_FLAG_OBJECT_INHERIT = 1, " \
						+ "ACE_FLAG_CONTAINER_INHERIT = 2, " \
						+ "ACE_FLAG_NO_PROPAGATE = 4, " \
						+ "ACE_FLAG_INHERIT_ONLY = 8, " \
						+ "ACE_FLAG_INHERITED = 16, " \
						+ "ACE_FLAG_NOTDOCUMENTED = 32, " \
						+ "ACE_FLAG_SUCCESSFUL_ACCESS = 64 " \
						+ "ACE_FLAG_FAILED_ACCESS = 128 ")
	#check mask validity
	if intMask not in (ADS_RIGHT_DS_CREATE_CHILD, \
					ADS_RIGHT_DS_DELETE_CHILD, \
					ADS_RIGHT_DS_SELF, \
					ADS_RIGHT_DS_READ_PROP, \
					ADS_RIGHT_DS_WRITE_PROP, \
					ADS_RIGHT_DS_CONTROL_ACCESS):
		raise Exception("The mask provided to constructObjectACE was not valid. " \
						+ "Object ACE Masks include ONE of the following flags: " \
						+ "ADS_RIGHT_DS_CREATE_CHILD=1, "
						+ "ADS_RIGHT_DS_DELETE_CHILD=2, "
						+ "ADS_RIGHT_DS_SELF=8, "
						+ "ADS_RIGHT_DS_READ_PROP=16, "
						+ "ADS_RIGHT_DS_WRITE_PROP=32, "
						+ "ADS_RIGHT_DS_CONTROL_ACCESS=256")

	#check sid validity
	if not SIDOperations.sidIsValid(trusteeSIDBytes):
		raise Exception("The provided SID is not valid.  See http://msdn.microsoft.com/en-us/library/gg465313.aspx for correct SID structure.")
	
	#Everything checks out - create the ACE
	#aceSize is two bytes and the least multiple of four greater than or equal to the actual size of the entire ACE, which is TBD so we enter
	#zeroes for placeholders for now
	aceTypeByte = struct.pack("<B",intAceType)
	aceFlagsByte = struct.pack("<B",intAceFlags)
	aceSizeBytes = struct.pack("<H",0) #2-bytes, TBD after finished building entire ACE
	maskBytes = struct.pack("<I",intMask)

	intObjectFlags = 0
	if objectTypeUUID is not None:
		intObjectFlags+=1
		objectTypeBytes = objectTypeUUID.bytes_le
	else:
		objectTypeBytes = ""
	if inheritedObjectTypeUUID is not None:
		intObjectFlags+=2
		inheritedObjectTypeBytes = inheritedObjectTypeUUID.bytes_le
	else:
		inheritedObjectTypeBytes = ""
	
	objectTypeFlagsBytes = struct.pack("<I",intObjectFlags)

	#Size of the ace depends on whether or not objectType and inheritedObjectType GUIDs are present.
	if intObjectFlags == 0:
		aceActualSize = 12+len(trusteeSIDBytes)+len(appDataBytes)
	elif intObjectFlags in (ACE_OBJECT_TYPE_PRESENT,ACE_INHERITED_OBJECT_TYPE_PRESENT):
		aceActualSize = 28+len(trusteeSIDBytes)+len(appDataBytes)
	else:	
		aceActualSize = 44+len(trusteeSIDBytes)+len(appDataBytes)

	if aceActualSize % 4 <> 0:
		#print "Ace actual size (" + str(aceActualSize) + ") is not a divisor of 4."
		aceByteSize = int(aceActualSize/4)*4+4
		#print "Setting byte size to: " + str(aceByteSize)
	else:
		aceByteSize = aceActualSize
		
	aceSizeBytes = struct.pack("<H",aceByteSize)
	newAceBytes = aceTypeByte+aceFlagsByte+aceSizeBytes+maskBytes+objectTypeFlagsBytes+objectTypeBytes+inheritedObjectTypeBytes+trusteeSIDBytes+appDataBytes
	return newAceBytes

def constructSystemMandatoryLabelACE(flags,mask,trusteeSIDBytes):
	"""
	Do not use, this method is not yet implemented.
	"""
	raise Exception("System Mandatory Label ACEs are not implemented.")

def constructSystemResourceAttributeACE(flags,mask,trusteeSIDBytes,attributeData):
	"""
	Do not use, this method is not yet implemented.
	"""
	raise Exception("System Resource Attribute ACEs are not implemented.")

def constructSystemScopedPolicyIdACE(flags,mask,trusteeSIDBytes):
	"""
	Do not use, this method is not yet implemented.
	"""
	raise Exception("System Scoped Policy ID ACEs are not implemented.")

def getACEType(aceBytes):
	"""
	Given a bytestring representing an ACE, return the ACE type (as an integer)
	"""
	return struct.unpack("<B",aceBytes[0])[0]
		
def getACEFlags(aceBytes):
	"""
	Given a bytestring representing an ACE, return the ACE flags (as an integer)
	"""
	return struct.unpack("<B",aceBytes[1])[0]

def getACELength(aceBytes):
	"""
	Given a bytestring representing an ACE, return the length in bytes reported by the ACE (as an integer)
	"""
	return struct.unpack("<H",aceBytes[2:4])[0]

def getACEMask(aceBytes):
	"""
	Given a bytestring representing an ACE, return the ACE Mask (as an integer)
	"""
	return struct.unpack("<I",aceBytes[4:8])[0]

def getACEObjectTypeFlags(aceBytes):
	"""
	Given a bytestring representing an ACE, return the ACE objectTypeFlags (as an integer)
	"""
	if getACEType(aceBytes) not in (ACE_TYPE_ACCESS_ALLOWED_OBJECT, \
														  ACE_TYPE_ACCESS_DENIED_OBJECT, \
														  ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT, \
														  ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, \
														  ACE_TYPE_SYSTEM_AUDIT_OBJECT, \
														  ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
		raise Exception("The ACE provided does not contain objectType information.")
	
	return struct.unpack("<I",aceBytes[8:12])[0]

def getACEObjectType(aceBytes):
	"""
	Given a bytestring representing an ACE, return the ACE objectType GUID (as UUID)
	"""
	#make sure the ACEtype supports objectType and objectType is valid
	if getACEType(aceBytes) not in (ACE_TYPE_ACCESS_ALLOWED_OBJECT, \
														  ACE_TYPE_ACCESS_DENIED_OBJECT, \
														  ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT, \
														  ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, \
														  ACE_TYPE_SYSTEM_AUDIT_OBJECT, \
														  ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
		raise Exception("The ACE provided does not contain objectType information.")
	
	if aceObjectTypeIsValid(aceBytes):
		#bytes 12-27
		return uuid.UUID(bytes_le=aceBytes[12:28])
	else:
		raise Exception("The ACE provided does not contain objectType information.")

def getACEInheritedObjectType(aceBytes):
	"""
	Given a bytestring representing an ACE, return the ACE InheritedObjectType GUID (as UUID)
	"""
	#make sure the ACEtype supports inheritedObjectType and inheritedObjectType is valid
	if getACEType(aceBytes) not in (ACE_TYPE_ACCESS_ALLOWED_OBJECT, \
									ACE_TYPE_ACCESS_DENIED_OBJECT, \
									ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT, \
									ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, \
									ACE_TYPE_SYSTEM_AUDIT_OBJECT, \
									ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
		raise Exception("The ACE provided does not contain inheritedObjectType information.")
	if not aceInheritedObjectTypeIsValid(aceBytes):
		raise Exception("The ACE provided specifies that the inheritedObjectType is not valid.")
	
	objectFlags = struct.unpack("<I",aceBytes[12:16])
	if objectFlags == ACE_INHERITED_OBJECT_TYPE_PRESENT:
		#bytes 12-27
		return uuid.UUID(bytes_le=aceBytes[12:28])
	elif objectFlags == ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT:
		#bytes 28-43
		return uuid.UUID(bytes_le=aceBytes[28:44])

def getACETrusteeSID(aceBytes):
	"""
	TODO: Implement
	Return the bytes of the SID representing the trustee in the ACE
	"""
	#requires us to find out what kind of ACE it is so we know where to look for the SID
	aceType = getACEType(aceBytes)
		
	if aceType in (ACE_TYPE_ACCESS_ALLOWED, \
				   ACE_TYPE_ACCESS_DENIED, \
				   ACE_TYPE_SYSTEM_AUDIT, \
				   ACE_TYPE_SYSTEM_MANDATORY_LABEL, \
				   ACE_TYPE_SYSTEM_SCOPED_POLICY_ID, \
				   ACE_TYPE_ACCESS_ALLOWED_CALLBACK, \
				   ACE_TYPE_ACCESS_DENIED_CALLBACK, \
				   ACE_TYPE_SYSTEM_AUDIT_CALLBACK, \
				   ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE):
		#bytes 8 and up describe the SID
		aceSIDOffset = 8 	
	elif aceType in (ACE_TYPE_ACCESS_ALLOWED_OBJECT, \
					 ACE_TYPE_ACCESS_DENIED_OBJECT, \
					 ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT, \
					 ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, \
					 ACE_TYPE_SYSTEM_AUDIT_OBJECT, \
					 ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
		#note: if objectflags is not == 3, then the sid offset is affected
		#if objectflags is 1 or 2, then chop off 16 bytes (one of two objectguids is missing).  If objectflags is 0, chop off 32 bytes (both objectguids missing)
		objectflags = getACEObjectTypeFlags(aceBytes)
		if objectflags == 0:
			aceSIDOffset=12
		elif objectflags in (ACE_OBJECT_TYPE_PRESENT, \
							 ACE_INHERITED_OBJECT_TYPE_PRESENT):
			aceSIDOffset=28
		elif objectflags == ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT:
			aceSIDOffset=44
			
	else:
		raise Exception("Invalid or unknown ACE Type")
	
	#sub authority count is the 2nd byte in the sid and determines the length
	aceSIDSubAuthCount = struct.unpack("<B",aceBytes[aceSIDOffset+1])[0] 
	#The first 8 bytes of a SID are always reserved for describing revision,subauthority count and identifier authority.
	#From that point on, each sub-authority is always 4 bytes long.  
	#So 4 * the sub authority count + 8 initial bytes = SID size in bytes
	aceSIDLength = 8 + 4*aceSIDSubAuthCount 
	return aceBytes[aceSIDOffset:aceSIDOffset+aceSIDLength]
	
def aceFlagsString(intAceFlags):
	"""
	Given the integer representation of an ACE Flags bitfield, return the selected mask options as a descriptor string.
	"""
	lstFlags = []
	if (intAceFlags & ACE_FLAG_OBJECT_INHERIT) == ACE_FLAG_OBJECT_INHERIT:
		lstFlags.append("ACE_FLAG_OBJECT_INHERIT")
	if (intAceFlags & ACE_FLAG_CONTAINER_INHERIT) == ACE_FLAG_CONTAINER_INHERIT:
		lstFlags.append("ACE_FLAG_CONTAINER_INHERIT")
	if (intAceFlags & ACE_FLAG_NO_PROPAGATE) == ACE_FLAG_NO_PROPAGATE:
		lstFlags.append("ACE_FLAG_NO_PROPAGATE")
	if (intAceFlags & ACE_FLAG_INHERIT_ONLY) == ACE_FLAG_INHERIT_ONLY:
		lstFlags.append("ACE_FLAG_INHERIT_ONLY")
	if (intAceFlags & ACE_FLAG_INHERITED) == ACE_FLAG_INHERITED:
		lstFlags.append("ACE_FLAG_INHERITED")
	if (intAceFlags & ACE_FLAG_NOTDOCUMENTED) == ACE_FLAG_NOTDOCUMENTED:
		lstFlags.append("ACE_FLAG_NOTDOCUMENTED")
	if (intAceFlags & ACE_FLAG_SUCCESSFUL_ACCESS) == ACE_FLAG_SUCCESSFUL_ACCESS:
		lstFlags.append("ACE_FLAG_SUCCESSFUL_ACCESS")
	if (intAceFlags & ACE_FLAG_FAILED_ACCESS) == ACE_FLAG_FAILED_ACCESS:
		lstFlags.append("ACE_FLAG_FAILED_ACCESS")
	return " | ".join(lstFlags)
	
def aceObjectTypeFlagsString(intAceObjectTypeFlags):
	"""
	Given the integer representation of an ACE objectFlags bitfield, return the selected mask options as a descriptor string.
	"""
	lstFlags = []
	if (intAceObjectTypeFlags & ACE_OBJECT_TYPE_PRESENT) == ACE_OBJECT_TYPE_PRESENT:
		lstFlags.append("ACE_OBJECT_TYPE_PRESENT")
	if (intAceObjectTypeFlags & ACE_INHERITED_OBJECT_TYPE_PRESENT) == ACE_INHERITED_OBJECT_TYPE_PRESENT:
		lstFlags.append("ACE_INHERITED_OBJECT_TYPE_PRESENT")
	return " | ".join(lstFlags)

def aceMaskString(intAceMask):
	"""
	Given the integer representation of an ACE Mask, return the selected mask options as a descriptor string.
	"""
	lstMasks = []
	
	if (intAceMask & ACCESS_MASK_GENERIC_READ) == ACCESS_MASK_GENERIC_READ:
		lstMasks.append("ACCESS_MASK_GENERIC_READ")
	if (intAceMask & ACCESS_MASK_GENERIC_WRITE) == ACCESS_MASK_GENERIC_WRITE:
		lstMasks.append("ACCESS_MASK_GENERIC_WRITE")
	if (intAceMask & ACCESS_MASK_GENERIC_EXECUTE) == ACCESS_MASK_GENERIC_EXECUTE:
		lstMasks.append("ACCESS_MASK_GENERIC_EXECUTE")
	if (intAceMask & ACCESS_MASK_GENERIC_ALL) == ACCESS_MASK_GENERIC_ALL:
		lstMasks.append("ACCESS_MASK_GENERIC_ALL")
	if (intAceMask & ACCESS_MASK_MAXIMUM_ALLOWED) == ACCESS_MASK_MAXIMUM_ALLOWED:
		lstMasks.append("ACCESS_MASK_MAXIMUM_ALLOWED")
	if (intAceMask & ACCESS_MASK_ACCESS_SYSTEM_SECURITY) == ACCESS_MASK_ACCESS_SYSTEM_SECURITY:
		lstMasks.append("ACCESS_MASK_ACCESS_SYSTEM_SECURITY")
	if (intAceMask & ACCESS_MASK_SYNCHRONIZE) == ACCESS_MASK_SYNCHRONIZE:
		lstMasks.append("ACCESS_MASK_SYNCHRONIZE")
	if (intAceMask & ACCESS_MASK_WRITE_OWNER) == ACCESS_MASK_WRITE_OWNER:
		lstMasks.append("ACCESS_MASK_WRITE_OWNER")
	if (intAceMask & ACCESS_MASK_WRITE_DACL) == ACCESS_MASK_WRITE_DACL:
		lstMasks.append("ACCESS_MASK_WRITE_DACL")
	if (intAceMask & ACCESS_MASK_READ_CONTROL) == ACCESS_MASK_READ_CONTROL:
		lstMasks.append("ACCESS_MASK_READ_CONTROL")
	if (intAceMask & ACCESS_MASK_DELETE) == ACCESS_MASK_DELETE:
		lstMasks.append("ACCESS_MASK_DELETE")
	if (intAceMask & ADS_RIGHT_DS_CREATE_CHILD) == ADS_RIGHT_DS_CREATE_CHILD:
		lstMasks.append("ADS_RIGHT_DS_CREATE_CHILD")
	if (intAceMask & ADS_RIGHT_DS_DELETE_CHILD) == ADS_RIGHT_DS_DELETE_CHILD:
		lstMasks.append("ADS_RIGHT_DS_DELETE_CHILD")
	if (intAceMask & ADS_RIGHT_DS_SELF) == ADS_RIGHT_DS_SELF:
		lstMasks.append("ADS_RIGHT_DS_SELF")
	if (intAceMask & ADS_RIGHT_DS_READ_PROP) == ADS_RIGHT_DS_READ_PROP:
		lstMasks.append("ADS_RIGHT_DS_READ_PROP")
	if (intAceMask & ADS_RIGHT_DS_WRITE_PROP) == ADS_RIGHT_DS_WRITE_PROP:
		lstMasks.append("ADS_RIGHT_DS_WRITE_PROP")
	if (intAceMask & ADS_RIGHT_DS_CONTROL_ACCESS) == ADS_RIGHT_DS_CONTROL_ACCESS:
		lstMasks.append("ADS_RIGHT_DS_CONTROL_ACCESS")
	return " | ".join(lstMasks)
	
def aceTypeName(intAceType):
	"""
	Given the integer representation of an ACE Type, return the type as a descriptor string.
	"""
	if intAceType == ACE_TYPE_ACCESS_ALLOWED:
		return "ACE_TYPE_ACCESS_ALLOWED"
	if intAceType == ACE_TYPE_ACCESS_DENIED:
		return "ACE_TYPE_ACCESS_DENIED"
	if intAceType == ACE_TYPE_SYSTEM_AUDIT:
		return "ACE_TYPE_SYSTEM_AUDIT"
	if intAceType == ACE_TYPE_SYSTEM_ALARM:
		return "ACE_TYPE_SYSTEM_ALARM"
	if intAceType == ACE_TYPE_ACCESS_ALLOWED_COMPOUND:
		return "ACE_TYPE_ACCESS_ALLOWED_COMPOUND"
	if intAceType == ACE_TYPE_ACCESS_ALLOWED_OBJECT:
		return "ACE_TYPE_ACCESS_ALLOWED_OBJECT"
	if intAceType == ACE_TYPE_ACCESS_DENIED_OBJECT:
		return "ACE_TYPE_ACCESS_DENIED_OBJECT"
	if intAceType == ACE_TYPE_SYSTEM_AUDIT_OBJECT:
		return "ACE_TYPE_SYSTEM_AUDIT_OBJECT"
	if intAceType == ACE_TYPE_SYSTEM_ALARM_OBJECT:
		return "ACE_TYPE_SYSTEM_ALARM_OBJECT"
	if intAceType == ACE_TYPE_ACCESS_ALLOWED_CALLBACK:
		return "ACE_TYPE_ACCESS_ALLOWED_CALLBACK"
	if intAceType == ACE_TYPE_ACCESS_DENIED_CALLBACK:
		return "ACE_TYPE_ACCESS_DENIED_CALLBACK"
	if intAceType == ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
		return "ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT"
	if intAceType == ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT:
		return "ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT"
	if intAceType == ACE_TYPE_SYSTEM_AUDIT_CALLBACK:
		return "ACE_TYPE_SYSTEM_AUDIT_CALLBACK"
	if intAceType == ACE_TYPE_SYSTEM_ALARM_CALLBACK:
		return "ACE_TYPE_SYSTEM_ALARM_CALLBACK"
	if intAceType == ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		return "ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT"
	if intAceType == ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
		return "ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT"
	if intAceType == ACE_TYPE_SYSTEM_MANDATORY_LABEL:
		return "ACE_TYPE_SYSTEM_MANDATORY_LABEL"
	if intAceType == ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		return "ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE"
	if intAceType == ACE_TYPE_SYSTEM_SCOPED_POLICY_ID:
		return "ACE_TYPE_SYSTEM_SCOPED_POLICY_ID"
	else:
		return "ACE_TYPE_INVALID"

def aceObjectTypeIsValid(aceBytes):
	"""
	Given a bytestring representing an ACE, return true if the ace contains objectType data, false if not
	"""
	if getACEType(aceBytes) in (ACE_TYPE_ACCESS_ALLOWED_OBJECT, \
														  ACE_TYPE_ACCESS_DENIED_OBJECT, \
														  ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT, \
														  ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, \
														  ACE_TYPE_SYSTEM_AUDIT_OBJECT, \
														  ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
		objectFlags = struct.unpack("<I",aceBytes[8:12])
		#print "ace is an object ace... checking to see if its got object-type-present flag set etc"
		aceObjectTypeFlags = getACEObjectTypeFlags(aceBytes)
		#print "ace objecttypeflags value: " + aceObjectTypeFlags
		if aceObjectTypeFlags in (ACE_OBJECT_TYPE_PRESENT, \
								  ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT):
			
			return True
		else:
			return False
	else:
		return False
	
def aceInheritedObjectTypeIsValid(aceBytes):
	"""
	Given a bytestring representing an ACE, return true if the ace contains inheritedobjectType data, false if not
	"""
	if getACEType(aceBytes) in (ACE_TYPE_ACCESS_ALLOWED_OBJECT, \
														  ACE_TYPE_ACCESS_DENIED_OBJECT, \
														  ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT, \
														  ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, \
														  ACE_TYPE_SYSTEM_AUDIT_OBJECT, \
														  ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
		objectFlags = struct.unpack("<I",aceBytes[8:12])[0]
		if objectFlags in (ACE_INHERITED_OBJECT_TYPE_PRESENT,ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT):
			return True
		else:
			return False
	else:
		return False

def aceIsInherited(aceBytes):
	"""
	Given a bytestring representing an ACE, return true if the ACE is inherited from a parent
	"""
	flags = getACEFlags(aceBytes)
	
	if (flags & ACE_FLAG_INHERITED) == ACE_FLAG_INHERITED:
		return True
	else:
		return False

def aceIsDeny(aceBytes):
	"""
	Given a bytestring representing an ACE, return true if the ACE is a DENY ACE
	"""
	aceType = getACEType(aceBytes)
	
	if aceType in (ACE_TYPE_ACCESS_DENIED, \
					ACE_TYPE_ACCESS_DENIED_OBJECT, \
					ACE_TYPE_ACCESS_DENIED_CALLBACK, \
					ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT):
		return True
	else:
		return False

def aceIsInheritable(aceBytes):
	"""
	Given a bytestring representing an ACE, return true if the ACE is inheritable
	"""
	aceFlags = getACEFlags(aceBytes)
	
	if (aceFlags & ACE_FLAG_OBJECT_INHERIT) == ACE_FLAG_OBJECT_INHERIT:
		return True
	if (aceFlags & ACE_FLAG_CONTAINER_INHERIT) == ACE_FLAG_CONTAINER_INHERIT:
		return True
	if (aceFlags & ACE_FLAG_INHERIT_ONLY) == ACE_FLAG_INHERIT_ONLY:
		return True
	return False

def aceDefinesObjectRights(aceBytes):
	"""
	Given a bytestring representing an ACE, return true if the ACE defines object rights or false if it defines property or child-object rights
	"""
	if aceObjectTypeIsValid(aceBytes):
		return True
	else:
		return False

def aceInfo(aceBytes):
	"""
	Utility method that returns a tuple of details on the given ACE
	"""
	aceType = getACEType(aceBytes)
	lstDetails =  [("ACE Type", aceTypeName(aceType)), \
				   ("ACE Flags", aceFlagsString(getACEFlags(aceBytes))), \
				   ("ACE Mask", aceMaskString(getACEMask(aceBytes))), \
				   ("ACE Trustee", SIDOperations.bytesAsReadableSID(getACETrusteeSID(aceBytes))), \
				   ("ACE Inherited?", aceIsInherited(aceBytes)), \
				   ("ACE Rank", aceRank(aceBytes))]
				   
	if aceType in (ACE_TYPE_ACCESS_ALLOWED_OBJECT, \
				   ACE_TYPE_ACCESS_DENIED_OBJECT, \
				   ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT, \
				   ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, \
				   ACE_TYPE_SYSTEM_AUDIT_OBJECT, \
				   ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT):
		lstDetails.append(("ACE Object Type Flags", aceObjectTypeFlagsString(getACEObjectTypeFlags(aceBytes))))
		if aceObjectTypeIsValid(aceBytes): 
			lstDetails.append(("ACE Object Type", str(getACEObjectType(aceBytes))))
		if aceInheritedObjectTypeIsValid(aceBytes):
			lstDetails.append(("ACE Inherited Object Type", str(getACEInheritedObjectType(aceBytes))))
	return lstDetails

def aceRank(aceBytes):
	"""
	Returns a rank for the given ACE so it can be sorted properly in its parent ACL
	Which position an ACE is assigned in the ACL is determined by the following factors:
				
			-Explicit ACEs:
					-DENY ACEs:
						-object ACEs
						-property ACEs
					-GRANT ACEs:
						-object ACEs
						-property ACEs
			-*TODO: NOT YET IMPLEMENTED* Inherited ACEs:
				-Inherited ACEs are stored in the order in which they were inherited
		 			-ACEs inherited from the child object's parent come first
		 				-DENY ACEs
		 					-object ACEs
		 					-property ACEs
		 				-GRANT ACEs
		 					-object ACES
		 					-property ACES
		 			-ACEs inherited from the grandparent
		 				-DENY ACEs
		 					-object ACEs
		 					-property ACEs
		 				-GRANT ACEs
		 					-object ACES
		 					-property ACES
		 			-Great-Grandparent
		 				.
		 				.
		 				.
						
	"""
	bAceIsInherited = aceIsInherited(aceBytes)
	bAceIsDeny = aceIsDeny(aceBytes)
	bAceDefinesObjectRights = aceDefinesObjectRights(aceBytes)
	
	rank = 0
	
	if bAceIsInherited:
		rank += 1000000
	else:
		rank += 2000000
	if rank == 2000000:
		if bAceIsDeny:
			rank += 200000
		else: 
			rank += 100000
		if bAceDefinesObjectRights:
			rank += 20000
		else:
			rank += 10000
	
	return rank
