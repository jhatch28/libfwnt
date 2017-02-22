import struct

"""SID Structure Integer Constants"""
#Valid Primary Authorities for SIDs
SID_AUTHORITY_NULL=0
SID_AUTHORITY_WORLD=1
SID_AUTHORITY_LOCAL=2
SID_AUTHORITY_CREATOR=3
SID_AUTHORITY_NON_UNIQUE=4
SID_AUTHORITY_SECURITY_NT=5
SID_AUTHORITY_SECURITY_APP_PACKAGE=15
SID_AUTHORITY_SECURITY_MANDATORY_LABEL=16


def readableSIDAsBytes(strReadableSID):
	"""
	Given a readable SID, return the SID as a bytestring
	"""
		
	if not strReadableSID.startswith("S-"):
		raise Exception("Malformed Readable SID: " + strReadableSID + ".  Must start with 'S-'.")
	
	lstReadableSID = strReadableSID.split("-")
	barray = bytearray([int(lstReadableSID[1]),len(lstReadableSID[3:]),0,0,0,0,0,int(lstReadableSID[2])])
	for i in lstReadableSID[3:]:
		intSubAuth = int(i)
		subAuthBytes = struct.pack("<I",intSubAuth)
		barray.extend(bytearray(subAuthBytes))
	#after converting to bytes, check validity
	if not sidIsValid(str(barray)):
		raise Exception("Malformed SID.")
	return str(barray)

def bytesAsReadableSID(strBytes):
	"""
	Given a bytestring representing a SID, return the SID in human-readable form
	"""
	#verify that the SID bytes are valid first
	if not sidIsValid(strBytes):
		raise Exception("Malformed SID: " + '\\x' + '\\x'.join('{:02X}'.format(i) for i in bytearray(strBytes)))
	subAuthorityCount = struct.unpack("<B",strBytes[1])[0]
	lstReadableSID=["S",str(struct.unpack("<B",strBytes[0])[0])]
	#authority
	lstReadableSID.append(str(struct.unpack("<B",strBytes[7])[0]))
	#subauthorities
	for i in range(0,subAuthorityCount):
		n = 4*i+8
		lstReadableSID.append(str(struct.unpack("<I",strBytes[n:n+4])[0]))
	return "-".join(lstReadableSID)

def bytesAsLDAPQuerySID(strBytes):
	"""
	Given a bytestring representing a SID, return the SID as a readable string in LDAP query format
	"""
	
	#verify that the SID bytes are valid first
	if not sidIsValid(strBytes):
		raise Exception("Malformed SID: " + '\\x' + '\\x'.join('{:02X}'.format(i) for i in bytearray(strBytes)))
	return '\\' + '\\'.join('{:02X}'.format(i) for i in bytearray(strBytes))

def sidIsValid(sidBytes):
	"""
	Returns true if provided bytes representing a SID conform to specification described at:
	http://msdn.microsoft.com/en-us/library/gg465313.aspx
	"""
	
	#byte 0 should always be 0x1 (stands for revision 1)
	if sidBytes[0] <> '\x01':
		#print "first byte of sid is not 0x1"
		return False
	#byte 1 represents number of sub authorities (number of dashes in the readable sid minus the first two)
	#the range of valid subauthority counts is 0-15, so...
	subAuthorityCount = struct.unpack("<B",sidBytes[1])[0]
	if subAuthorityCount > 15:
		return False
	#bytes 2 thru 7 identify the main authority of the sid, and falls under one of a small number of specific values:
	#2 thru 5 should always represent an integer value of 0 (be zeroed out)
	if struct.unpack(">I",sidBytes[2:6])[0] > 0:
		return False
	#6 and 7 as a short integer should fall within the sid authority values listed
	if struct.unpack(">H",sidBytes[6:8])[0] not in (SID_AUTHORITY_NULL, \
													SID_AUTHORITY_WORLD, \
													SID_AUTHORITY_LOCAL, \
													SID_AUTHORITY_CREATOR, \
													SID_AUTHORITY_NON_UNIQUE, \
													SID_AUTHORITY_SECURITY_NT, \
													SID_AUTHORITY_SECURITY_APP_PACKAGE, \
													SID_AUTHORITY_SECURITY_MANDATORY_LABEL):
		return False
	#bytes 8 and up represent the sub-authorities ... 
	#The number of bytes in the subauthority range should be four times the sub-authority count previously indicated
	subAuthorityBytesLength = len(sidBytes[8:])
	if subAuthorityBytesLength <> (4*subAuthorityCount):
		return False
	
	return True

def getSidSubAuthorityCount(sidBytes):
	"""
	Returns the integer representation of the subAuthorityCount for the provided SID
	"""
	return struct.unpack("<B",sidBytes[1])[0]
