#!/usr/bin/env python2.7
from scapy.all import *
from utility.wpa_struct_for_scapy import *
from utility.util import *

from Crypto.Hash import HMAC , SHA
from Crypto.Cipher import ARC4
from crypto.util import *

import binascii
import inspect

class HandleEAPoL:
	""" Handle Extensible Authentication Protocol (EAP) over LAN (EAPoL) Frames.
	"""
				
	######################################################################################
	### Initializer ######################################################################
	######################################################################################
	
	def __init__( self , logger , iface , addr1 , addr2 , addr3 , ssid ):
		""" Initializer.
		"""
		self.logger		= logger
		self.iface 		= iface
		self.addr1 		= addr1
		self.addr2		= addr2
		self.addr3 		= addr3
		self.broadcast		= 'ff:ff:ff:ff:ff:ff'
		self.ssid 		= ssid
		
		# Settings
		self.passphrase		= None
		self.ANonce		= None
		self.SNonce		= os.urandom( 32 ) # Random 32-octet nonce.
		self.A			= 'Pairwise key expansion'
		self.B			= None
		self.keyID		= 'idx0' # The default Key Identifier.
		
		# Replay Counter
		self.replayCounter 	= 0
		
		# Keys
		self.PMK	= None	# Pairwise Master Key
		self.PTK	= None	# Pairwise Transient Key
		self.KCK	= None	# EAPOL-Key Confirmation Key
		self.KEK	= None	# EAPOL-Key Encryption Key
		self.TK		= None	# Temporal Key
		self.MMICTxK	= None	# Michael MIC Authenticator Tx Key
		self.MMICRxK	= None	# Michael MIC Authenticator Rx Key
		self.GTK	= None	# Group Temporal Key
		
		# Handlers for cryptographic encapsulation and decapsulation.
		self.handleTKIP	= None
		self.handleAES	= None
		
	def setPassphrase( self , passphrase ):
		""" Set the passphrase used in TKIP and AES, and generate the PMK.
		"""
		self.passphrase	= passphrase
		
		# Generate and log the generated PMK.
		self.PMK = pbkdf2_bin( self.passphrase , self.ssid , 4096 , 32 )
		self.logger.logKey( 'Pairwise Master Key' , self.PMK )
	
	def setCryptographicHandlers( self , tkip = None , aes = None ):
		""" Set the cryptographic handlers for encapsulation and decapsulation.
		"""
		self.handleTKIP = tkip
		self.handleAES 	= aes
		
	def __assertWPAKeyMIC( self , packet , digest ):
		""" Assert that the EAPoL WPA Key layer has a valid MIC.
		"""
		
		# Get the Key Information and assert that the MIC bit was set.
		keyinfo 	= packet.getlayer( EAPOL_WPAKey ).KeyInfo
		flaglist 	= self.__getFlaglist( keyinfo )
		assert( 'mic' in flaglist ), \
			'The MIC flag in the EAPoL WPA Key layer was not set.'
		
		# Save the received MIC.
		micReceived 	= packet.getlayer( EAPOL_WPAKey ).WPAKeyMIC
		
		# Retrieve the EAPoL layer and clear its original MIC.
		# Re-calculate the MIC over the resulting string.
		eapolPacket 	= packet.getlayer( EAPOL )
		eapolPacket.getlayer( EAPOL_WPAKey ).WPAKeyMIC = '\x00'*16
		data 		= str( eapolPacket )
		micCalculated 	= HMAC.new( self.KCK , msg=data , digestmod=digest )
		micCalculated 	= micCalculated.digest()[:16]
		
		# Assert the integrity by comparing the original and calculated digest.
		assert( micReceived == micCalculated ), \
			'The received WPA Key MIC "%s" does not match the calculated WPA Key MIC ' \
			 '"%s".' % ( micReceived.encode('hex') , micCalculated.encode('hex') )
	
	def __getKeyInformation( self , flaglist ):
		""" Generates the integer for the Key Information field. Note that not all the
		 	bits defined in the specification are supported here.
			Ref. IEEE 802.11i specification; EAPOL-Key frames.
		"""
		keyinfo = 0
		if 'HMAC_MD5_RC4' in flaglist:
			keyinfo = setBit( keyinfo , 0 )
		if 'HMAC_SHA1_AES' in flaglist:
			keyinfo = setBit( keyinfo , 1 )
		if 'group' in flaglist:
			pass
		if 'pairwise' in flaglist:
			keyinfo = setBit( keyinfo , 3 )
		if 'idx0' in flaglist:
			pass
		if 'idx1' in flaglist:
			keyinfo = setBit( keyinfo , 4 )
		if 'idx2' in flaglist:
			keyinfo = setBit( keyinfo , 5 )
		if 'install' in flaglist:
			keyinfo = setBit( keyinfo , 6 )
		if 'ack' in flaglist:
			keyinfo = setBit( keyinfo , 7 )
		if 'mic' in flaglist:
			keyinfo = setBit( keyinfo , 8 )
		if 'secure' in flaglist:
			keyinfo = setBit( keyinfo , 9 )
		if 'error' in flaglist:
			keyinfo = setBit( keyinfo , 10 )
		if 'request' in flaglist:
			keyinfo = setBit( keyinfo , 11 )
		if 'encrypted' in flaglist:
			keyinfo = setBit( keyinfo , 12 )
		return keyinfo
	
	def __getFlaglist( self , keyinfo ):
		""" Generates the flaglist from the Key Information field. Note that not all the
		 	bits defined in the specification are supported here.
			Ref. IEEE 802.11i specification; EAPOL-Key frames.
		"""
		flaglist = []
		if( getBit( keyinfo , 0 ) == 1 ):
			flaglist.append( 'HMAC_MD5_RC4' )
		if( getBit( keyinfo , 1 ) == 1 ):
			flaglist.append( 'HMAC_SHA1_AES' )
		if( getBit( keyinfo , 3 ) == 0 ):
			flaglist.append( 'group' )
		if( getBit( keyinfo , 3 ) == 1 ):
			flaglist.append( 'pairwise' )
		if( getBit( keyinfo , 4 ) == 0 and getBit( keyinfo , 5 ) == 0 ):
			flaglist.append( 'idx0' )
		if( getBit( keyinfo , 4 ) == 1 ):
			flaglist.append( 'idx1' )
		if( getBit( keyinfo , 5 ) == 1 ):
			flaglist.append( 'idx2' )
		if( getBit( keyinfo , 6 ) == 1 ):
			flaglist.append( 'install' )
		if( getBit( keyinfo , 7 ) == 1 ):
			flaglist.append( 'ack' )
		if( getBit( keyinfo , 8 ) == 1 ):
			flaglist.append( 'mic' )
		if( getBit( keyinfo , 9 ) == 1 ):
			flaglist.append( 'secure' )
		if( getBit( keyinfo , 10 ) == 1 ):
			flaglist.append( 'error' )
		if( getBit( keyinfo , 11 ) == 1 ):
			flaglist.append( 'request' )
		if( getBit( keyinfo , 12 ) == 1 ):
			flaglist.append( 'encrypted' )
		return flaglist
		
	def __setKeyIDFromFlaglist( self , flaglist ):
		""" Set the key ID from the flaglist.
		"""
		if 'idx0' in flaglist:
			self.keyID = 'idx0'
		if 'idx1' in flaglist:
			self.keyID = 'idx1'
		if 'idx2' in flaglist:
			self.keyID = 'idx2'
		
	######################################################################################
	### Four Way Handshake ###############################################################
	######################################################################################
	
	# ------------------------------------------------------------------------------------
	# --- Four Way Handshake 1/4 ---------------------------------------------------------
	# ------------------------------------------------------------------------------------

	def fw_handshake_1_4( self , packet ):
		""" 4-Way Handshake 1/4.
		"""
		# Check if the Frame Check Sequence (FCS) flag is set in the Radiotap header, and
		# if so assert the correctness of the FCS.
		radiotapFCSFlag	= hasFCS( packet )
		if radiotapFCSFlag is True:
			assertDot11FCS( packet )
			packet.getlayer( EAPOL_WPAKey ).remove_payload() # Remove the FCS.
		
		# Assert on the flags in the Key Information to verify it is FWHS Message 1/4.
		# It is either HMAC_MD5_RC4 or HMAC_SHA1_AES.
		flaglist 	= self.__getFlaglist( packet.getlayer( EAPOL_WPAKey ).KeyInfo )
		errorMessage 	= 'The received packet is not 4-Way Handshake Message 1/4.'
		assert( 'pairwise' in flaglist ), 	errorMessage
		assert( 'install' not in flaglist ), 	errorMessage
		assert( 'ack' in flaglist ), 		errorMessage
		assert( 'mic' not in flaglist ), 	errorMessage
		assert( 'secure' not in flaglist ), 	errorMessage
		self.logger.log( self.logger.RECEIVED , 'EAPOL 4-Way Handshake Message 1/4' )
		
		# Retrieve the authenticator nonce and calculate the pre-requirements for the PTK.
		nonce 		= packet.getlayer( EAPOL_WPAKey ).Nonce
		addr1		= binascii.a2b_hex( self.addr1.replace( ':' , '' ) )
		addr2		= binascii.a2b_hex( self.addr2.replace( ':' , '' ) )
		self.ANonce	= binascii.a2b_hex( nonce.encode('hex') )
		self.B		= min( addr1 , addr2 ) + max( addr1 , addr2 )
		self.B	       += min( self.ANonce , self.SNonce ) + max( self.ANonce , self. SNonce )
		
		# Update the Replay Counter.
		self.replayCounter = packet.getlayer( EAPOL_WPAKey ).ReplayCounter
		
		# Generate the PTK and set the KCK, KEK, TK, MMICTxK and MMICRxK.
		self.PTK	= customPRF512( self.PMK , self.A , self.B )
		self.KCK	= self.PTK[00:16]
		self.KEK	= self.PTK[16:32]
		self.TK		= self.PTK[32:48]
		self.MMICTxK	= self.PTK[48:56]
		self.MMICRxK	= self.PTK[56:64]
		
		# Log the generated keys.
		self.logger.logKey( 'Pairwise Transient Key' , self.PTK )
		self.logger.logKey( 'EAPOL-Key Confirmation Key' , self.KCK )
		self.logger.logKey( 'EAPOL-Key Encryption Key' , self.KEK )
		self.logger.logKey( 'Temporal Key' , self.TK )
		self.logger.logKey( 'Michael MIC Authenticator Tx Key' , self.MMICTxK )
		self.logger.logKey( 'Michael MIC Authenticator Rx Key' , self.MMICRxK )
	
	# ------------------------------------------------------------------------------------
	# --- Four Way Handshake 2/4 ---------------------------------------------------------
	# ------------------------------------------------------------------------------------
	
	def fw_handshake_2_4_tkip( self , vendor , eapolMIC = True , eapolMICFlag = True , customFlaglist = None , customRC = None ):
		""" 4-Way Handshake 2/4 (TKIP).
		"""
		parameterList = 'vendor=' + str(vendor) + ',eapolMIC=' + str(eapolMIC) + ',eapolMICFlag=' + str(eapolMICFlag) + ',customFlaglist=' + str(customFlaglist) + ',customRC=' + str(customRC)
		self.logger.log( self.logger.TRANSMIT , 'EAPOL 4-Way Handshake Message 2/4 TKIP (' + parameterList + ')')
		try:
		
			# Create an empty EAPOL WPA Key packet.
			packet 		= EAPOL( version=1 , type='EAPOL-Key' )/EAPOL_Key()/EAPOL_WPAKey()
			packetKey 	= packet.getlayer( EAPOL_WPAKey )
			if vendor != 'NONE':
				vendorInfo = Dot11Elt( ID='vendor' , info=getVendorInfo( type=vendor ) )
			flaglist = ['HMAC_MD5_RC4','idx0','pairwise']
			if eapolMICFlag is True:
				flaglist.append('mic')
			
			# Fill in the fields.
			if customFlaglist is not None:
				flaglist = customFlaglist
			packetKey.KeyInfo = self.__getKeyInformation( flaglist )
			if customRC is not None:
				if customRC == 'lower':	
					self.replayCounter -= 1
				elif customRC == 'higher':
					self.replayCounter += 1
			packetKey.ReplayCounter = self.replayCounter
			packetKey.Nonce = self.SNonce
			if vendor != 'NONE':
				packetKey.WPAKeyLength 	= len( vendorInfo )
				packetKey.WPAKey 	= vendorInfo
			
			# Calculate and add the MIC.
			if eapolMIC is True:
				mic = HMAC.new( self.KCK , msg=str( packet ) , digestmod=Crypto.Hash.MD5 )
				packetKey.WPAKeyMIC = mic.digest()
			
			# Transmit.
			sendp(RadioTap()/
				Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , type='Data' , subtype=0x00 , FCfield='to-DS' )/
				LLC( dsap=0xaa , ssap=0xaa , ctrl=0x03 )/
				SNAP( OUI=0x000000 , code=0x888e )/
				packet,
				iface=self.iface , verbose=False )
				
		except:
			raise
			
	def fw_handshake_2_4_aes( self , vendor , eapolMIC = True , eapolMICFlag = True , customFlaglist = None , customRC = None ):
		""" 4-Way Handshake 2/4 (WPA).
		"""
		parameterList = 'vendor=' + str(vendor) + ',eapolMIC=' + str(eapolMIC) + ',eapolMICFlag=' + str(eapolMICFlag) + ',customFlaglist=' + str(customFlaglist) + ',customRC=' + str(customRC)
		self.logger.log( self.logger.TRANSMIT , 'EAPOL 4-Way Handshake Message 2/4 AES (' + parameterList + ')')
		try:
		
			# Create an empty EAPOL WPA Key packet.
			packet 		= EAPOL( version=1 , type='EAPOL-Key' )/EAPOL_Key()/EAPOL_WPAKey()
			packetKey 	= packet.getlayer( EAPOL_WPAKey )
			if vendor != 'NONE':
				vendorInfo = Dot11Elt( ID='vendor' , info=getVendorInfo( type=vendor ) )
			flaglist	= ['HMAC_SHA1_AES','idx0','pairwise']
			if eapolMICFlag is True:
				flaglist.append('mic')
			
			# Fill in the fields.
			if customFlaglist is not None:
				flaglist = customFlaglist
			packetKey.KeyInfo = self.__getKeyInformation( flaglist )
			if customRC is not None:
				if customRC == 'lower':	
					self.replayCounter -= 1
				elif customRC == 'higher':
					self.replayCounter += 1
			packetKey.ReplayCounter 	= self.replayCounter
			packetKey.Nonce 		= self.SNonce
			if vendor != 'NONE':
				packetKey.WPAKeyLength 	= len( vendorInfo )
				packetKey.WPAKey 	= vendorInfo
			
			# Calculate and add the MIC.
			if eapolMIC is True:
				mic = HMAC.new( self.KCK , msg=str( packet ) , digestmod=Crypto.Hash.SHA )
				packetKey.WPAKeyMIC = mic.digest()
			
			# Transmit.
			sendp(RadioTap()/
				Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , type='Data' , subtype=0x00 , FCfield='to-DS' )/
				LLC( dsap=0xaa , ssap=0xaa , ctrl=0x03 )/
				SNAP( OUI=0x000000 , code=0x888e )/
				packet,
				iface=self.iface , verbose=False )
				
		except:
			raise
	
	# ------------------------------------------------------------------------------------
	# --- Four Way Handshake 3/4 ---------------------------------------------------------
	# ------------------------------------------------------------------------------------
			
	def fw_handshake_3_4_tkip( self , packet ):
		""" 4-Way Handshake 3/4 (TKIP).
		"""
		# Check if the Frame Check Sequence (FCS) flag is set in the Radiotap header, and
		# if so assert the correctness of the FCS.
		radiotapFCSFlag = hasFCS( packet )
		if radiotapFCSFlag is True:
			assertDot11FCS( packet )
			packet.getlayer( EAPOL_WPAKey ).remove_payload() # Remove the FCS.
			
		# Assert on the flags in the Key Information to verify it is FWHS Message 3/4.
		keyinfoReceived 	= packet.getlayer( EAPOL_WPAKey ).KeyInfo
		self.replayCounter	= packet.getlayer( EAPOL_WPAKey ).ReplayCounter
		flaglist		= ['HMAC_MD5_RC4','idx0','pairwise','install','ack','mic']
		keyinfoCalculated 	= self.__getKeyInformation( flaglist )
		assert( keyinfoReceived == keyinfoCalculated ), \
			'The received packet is not 4-Way Handshake Message 3/4.'
		self.logger.log( self.logger.RECEIVED , 'EAPOL 4-Way Handshake Message 3/4 TKIP' )
		
		# Assert that the EAPoL WPA Key layer has a valid MIC.
		self.__assertWPAKeyMIC( packet , Crypto.Hash.MD5 )
		
	def fw_handshake_3_4_aes( self , packet ):
		""" 4-Way Handshake 3/4 (WPA).
		"""
		# Check if the Frame Check Sequence (FCS) flag is set in the Radiotap header, and
		# if so assert the correctness of the FCS.
		radiotapFCSFlag = hasFCS( packet )
		if radiotapFCSFlag is True:
			assertDot11FCS( packet )
			packet.getlayer( EAPOL_WPAKey ).remove_payload() # Remove the FCS.
			
		# Assert on the flags in the Key Information to verify it is FWHS Message 3/4.
		keyinfoReceived 	= packet.getlayer( EAPOL_WPAKey ).KeyInfo
		self.replayCounter	= packet.getlayer( EAPOL_WPAKey ).ReplayCounter
		flaglist		= ['HMAC_SHA1_AES','idx0','pairwise','install','ack','mic']
		keyinfoCalculated 	= self.__getKeyInformation( flaglist )
		assert( keyinfoReceived == keyinfoCalculated ), \
			'The received packet is not 4-Way Handshake Message 3/4.'
		self.logger.log( self.logger.RECEIVED , 'EAPOL 4-Way Handshake Message 3/4 AES' )
			
		# Assert that the EAPoL WPA Key layer has a valid MIC.
		self.__assertWPAKeyMIC( packet , Crypto.Hash.SHA )
	
	# ------------------------------------------------------------------------------------
	# --- Four Way Handshake 4/4 ---------------------------------------------------------
	# ------------------------------------------------------------------------------------
	
	def fw_handshake_4_4_tkip( self , eapolMIC = True , eapolMICFlag = True , customFlaglist = None , addNonce = None , customRC = None , addData = None ):
		""" 4-Way Handshake 4/4 (TKIP).
			NOTE: 	IEEE 802.11i specification requires 'secure' flag. Works with and
				without, yet Wireshark does not identify message as 4/4 when the
				secure flag has been set.
		"""
		parameterList = 'eapolMIC=' + str(eapolMIC) + ',eapolMICFlag=' + str(eapolMICFlag) + ',customFlaglist=' + str(customFlaglist) + ',addNonce=' + str(addNonce) + ',customRC=' + str(customRC) + ',addData=' + str(addData)
		self.logger.log( self.logger.TRANSMIT , 'EAPOL 4-Way Handshake Message 4/4 TKIP (' + parameterList + ')')
		try:
						
			# Create an empty EAPOL WPA Key packet.
			packet 		= EAPOL( version=1 , type='EAPOL-Key' )/EAPOL_Key()/EAPOL_WPAKey()
			packetKey 	= packet.getlayer( EAPOL_WPAKey )
			flaglist 	= ['HMAC_MD5_RC4','idx0','pairwise']
			if eapolMICFlag is True:
				flaglist.append('mic')
			
			# Fill in the fields.
			if customFlaglist is not None:
				flaglist = customFlaglist
			packetKey.KeyInfo = self.__getKeyInformation( flaglist )
			if customRC is not None:
				if customRC == 'lower':	
					self.replayCounter -= 1
				elif customRC == 'higher':
					self.replayCounter += 1
			packetKey.ReplayCounter = self.replayCounter
			if addNonce is not None:
				if addNonce == 'supplicant':
					packetKey.Nonce = self.SNonce
				if addNonce == 'authenticator':
					packetKey.Nonce = self.ANonce
				if addNonce == 'random':
					packetKey.Nonce = binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
			if addData is not None:
				if addData == 'data':
					packetKey.WPAKeyLength 	= 32
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataNoLength':
					packetKey.WPAKeyLength 	= 0
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataShortLength':
					packetKey.WPAKeyLength 	= 16
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataLongLength':
					packetKey.WPAKeyLength 	= 48
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
			
			# Calculate and add the MIC.
			if eapolMIC is True:
				mic = HMAC.new( self.KCK , msg=str( packet ) , digestmod=Crypto.Hash.MD5 )
				packetKey.WPAKeyMIC = mic.digest()
			
			# Transmit.
			sendp(RadioTap()/
				Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , type='Data' , subtype=0x00 , FCfield='to-DS' )/
				LLC( dsap=0xaa , ssap=0xaa , ctrl=0x03 )/
				SNAP( OUI=0x000000 , code=0x888e )/
				packet,
				iface=self.iface , verbose=False )
			
		except:
			raise
			
	def fw_handshake_4_4_aes( self , eapolMIC = True , eapolMICFlag = True , customFlaglist = None , addNonce = None , customRC = None , addData = None ):
		""" 4-Way Handshake 4/4 (WPA).
			NOTE: 	IEEE 802.11i specification requires 'secure' flag. Works with and
				without, yet Wireshark does not identify message as 4/4 when the
				secure flag has been set.
		"""
		parameterList = 'eapolMIC=' + str(eapolMIC) + ',eapolMICFlag=' + str(eapolMICFlag) + ',customFlaglist=' + str(customFlaglist) + ',addNonce=' + str(addNonce) + ',customRC=' + str(customRC) + ',addData=' + str(addData)
		self.logger.log( self.logger.TRANSMIT , 'EAPOL 4-Way Handshake Message 4/4 AES (' + parameterList + ')')
		try:
					
			# Create an empty EAPOL WPA Key packet.
			packet 		= EAPOL( version=1 , type='EAPOL-Key' )/EAPOL_Key()/EAPOL_WPAKey()
			packetKey 	= packet.getlayer( EAPOL_WPAKey )
			flaglist	= ['HMAC_SHA1_AES','idx0','pairwise']
			if eapolMICFlag is True:
				flaglist.append('mic')
			
			# Fill in the fields.
			if customFlaglist is not None:
				flaglist = customFlaglist
			packetKey.KeyInfo = self.__getKeyInformation( flaglist )
			if customRC is not None:
				if customRC == 'lower':	
					self.replayCounter -= 1
				elif customRC == 'higher':
					self.replayCounter += 1
			packetKey.ReplayCounter = self.replayCounter
			if addNonce is not None:
				if addNonce == 'supplicant':
					packetKey.Nonce = self.SNonce
				if addNonce == 'authenticator':
					packetKey.Nonce = self.ANonce
				if addNonce == 'random':
					packetKey.Nonce = binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
			if addData is not None:
				if addData == 'data':
					packetKey.WPAKeyLength 	= 32
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataNoLength':
					packetKey.WPAKeyLength 	= 0
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataShortLength':
					packetKey.WPAKeyLength 	= 16
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataLongLength':
					packetKey.WPAKeyLength 	= 48
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
					
			# Calculate and add the MIC.
			if eapolMIC is True:
				mic = HMAC.new( self.KCK , msg=str( packet ) , digestmod=Crypto.Hash.SHA )
				packetKey.WPAKeyMIC = mic.digest()
			
			# Transmit.
			sendp(RadioTap()/
				Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , type='Data' , subtype=0x00 , FCfield='to-DS' )/
				LLC( dsap=0xaa , ssap=0xaa , ctrl=0x03 )/
				SNAP( OUI=0x000000 , code=0x888e )/
				packet,
				iface=self.iface , verbose=False )
			
		except:
			raise
	
	######################################################################################
	### Group Key Handshake ##############################################################
	######################################################################################
	
	# ------------------------------------------------------------------------------------
	# --- Group Key Handshake 1/2 --------------------------------------------------------
	# ------------------------------------------------------------------------------------
	
	def gk_handshake_1_2_tkip( self , packet ):
		""" Group Key Handshake 1/2 (TKIP).
		"""
		try:
			
			# Decapsulate the TKIP packet, and rebuild the plaintext packet.
			plaintext 		= self.handleTKIP.decapsulate( packet , self.TK , self.MMICTxK )
			packet 			= LLC()/SNAP()/EAPOL()/EAPOL_Key()/EAPOL_WPAKey()
			new_packet 		= packet.__class__( plaintext )
			
			# Assert on the flags in the Key Information to verify it is GKHS Message 1/2.
			keyinfoReceived 	= new_packet.getlayer( EAPOL_WPAKey ).KeyInfo
			self.__setKeyIDFromFlaglist( self.__getFlaglist( keyinfoReceived ) )
			flaglist		= ['HMAC_MD5_RC4','group','ack','mic','secure']
			flaglist.append( self.keyID ) # Copying the Key ID from the received packet.
			keyinfoCalculated 	= self.__getKeyInformation( flaglist )
			assert( keyinfoReceived == keyinfoCalculated ), \
				'The received packet is not Group Key Handshake Message 1/2.'
			self.logger.log( self.logger.RECEIVED , 'EAPOL Group Key Handshake Message 1/2 TKIP' )
			
			# Assert that the EAPoL WPA Key layer has a valid MIC.
			self.__assertWPAKeyMIC( new_packet , Crypto.Hash.MD5 )
			
			# Update the Replay Counter.
			self.replayCounter	= new_packet.getlayer( EAPOL_WPAKey ).ReplayCounter
			
			# Use ARC4 to decrypt the WPAKey-field, containing the Group Temporal Key.
			# First skip the first 256 bytes of ARC4, then decrypt the cipher.
			# Ref. IEEE 802.11i specification (2004); EAPOL-Key frames (Key Descriptor
			# Version 1).
			key		= new_packet.KeyIV + self.KEK
			arc4		= ARC4.new( key )
			arc4.decrypt( '\x00'*256 )
			self.GTK 	= arc4.decrypt( new_packet.WPAKey ) # Resulting key of 32 octets.
			self.logger.logKey( 'Group Temporal Key' , self.GTK )
			
		except:
			raise
	
	def gk_handshake_1_2_aes( self , packet ):
		""" Group Key Handshake 1/2 (WPA).
			The packet is decrypted with AES under the CTR with CBC-MAC Protocol (CCMP).
			CCM combines CTR for data confidentiality and CBC-MAC for authentication and 
			integrity.
		"""
		try:

			# Decapsulate the TKIP packet, and rebuild the plaintext packet.
			plaintext	= self.handleAES.decapsulate( packet , self.TK )
			packet 		= LLC()/SNAP()/EAPOL()/EAPOL_Key()/EAPOL_WPAKey()
			new_packet 	= packet.__class__( plaintext )
			
			# Assert on the flags in the Key Information to verify it is GKHS Message 1/2.
			keyinfoReceived 	= new_packet.getlayer( EAPOL_WPAKey ).KeyInfo
			self.__setKeyIDFromFlaglist( self.__getFlaglist( keyinfoReceived ) )
			flaglist		= ['HMAC_SHA1_AES','group','ack','mic','secure']
			flaglist.append( self.keyID ) # Copying the Key ID from the received packet.
			keyinfoCalculated 	= self.__getKeyInformation( flaglist )
			assert( keyinfoReceived == keyinfoCalculated ), \
				'The received packet is not Group Key Handshake Message 1/2.'
			self.logger.log( self.logger.RECEIVED , 'EAPOL Group Key Handshake Message 1/2 AES' )
			
			# Assert that the EAPoL WPA Key layer has a valid MIC.
			self.__assertWPAKeyMIC( new_packet , Crypto.Hash.SHA )

			# Update the Replay Counter.
			self.replayCounter	= new_packet.getlayer( EAPOL_WPAKey ).ReplayCounter
			
			# Retrieve the Group Temporal key.
			self.GTK = self.handleAES.unwrapKey( new_packet.WPAKey , self.KEK ) # Resulting key of 16/32 octets.
			self.logger.logKey( 'Group Temporal Key' , self.GTK )
			
		except:
			raise
		
	# ------------------------------------------------------------------------------------
	# --- Group Key Handshake 2/2 --------------------------------------------------------
	# ------------------------------------------------------------------------------------
	
	def gk_handshake_2_2_tkip( self , eapolMIC = True , eapolMICFlag = True , wepMIC = True , customFlaglist = None , addNonce = None , customRC = None , addData = None ):
		""" Group Key Handshake 2/2 (TKIP).
		"""
		parameterList = 'eapolMIC=' + str(eapolMIC) + ',eapolMICFlag=' + str(eapolMICFlag) + ',wepMIC=' + str(wepMIC) + ',customFlaglist=' + str(customFlaglist) + ',addNonce=' + str(addNonce) + ',customRC=' + str(customRC) + ',addData=' + str(addData)
		self.logger.log( self.logger.TRANSMIT , 'EAPOL Group Key Handshake Message 2/2 TKIP (' + parameterList + ')')
		try:
					
			# Create an empty EAPOL WPA Key packet.
			packet 		= EAPOL( version=1 , type='EAPOL-Key' )/EAPOL_Key()/EAPOL_WPAKey()
			packetKey 	= packet.getlayer( EAPOL_WPAKey )
			flaglist 	= ['HMAC_MD5_RC4','group','secure']
			flaglist.append( self.keyID )
			if eapolMICFlag is True:
				flaglist.append('mic')
			
			# Fill in the fields.
			if customFlaglist is not None:
				flaglist = customFlaglist
			packetKey.KeyInfo = self.__getKeyInformation( flaglist )
			if customRC is not None:
				if customRC == 'lower':	
					self.replayCounter -= 1
				elif customRC == 'higher':
					self.replayCounter += 1
			packetKey.ReplayCounter = self.replayCounter
			if addNonce is not None:
				if addNonce == 'supplicant':
					packetKey.Nonce = self.SNonce
				if addNonce == 'authenticator':
					packetKey.Nonce = self.ANonce
				if addNonce == 'random':
					packetKey.Nonce = binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
			if addData is not None:
				if addData == 'data':
					packetKey.WPAKeyLength 	= 32
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataNoLength':
					packetKey.WPAKeyLength 	= 0
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataShortLength':
					packetKey.WPAKeyLength 	= 16
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataLongLength':
					packetKey.WPAKeyLength 	= 48
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
					
			# Calculate and add the MIC.
			if eapolMIC is True:
				mic = HMAC.new( self.KCK , msg=str( packet ) , digestmod=Crypto.Hash.MD5 )
				packetKey.WPAKeyMIC = mic.digest()
			
			# Get the plaintext and generate the Logical-Link Control (LLC),
			# and Subnetwork Access Protocol (SNAP).
			plaintext	= str( packet )
			llcSnap		= LLC( dsap=0xaa , ssap=0xaa , ctrl=0x03 )
			llcSnap	   /= SNAP( OUI=0x000000 , code=0x888e )
			plaintext	= str( llcSnap ) + plaintext
			
			# Generate the dot11 header and request the encapsulated dot11wep message.
			dot11		= Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , FCfield='wep+to-DS' , type='Data' , subtype=0 )
			addr1 		= binascii.a2b_hex( self.addr1.replace( ':' , '' ) )
			addr2 		= binascii.a2b_hex( self.addr2.replace( ':' , '' ) )
			priority	= 0
			dot11wep 	= self.handleTKIP.encapsulate( plaintext , addr2 , addr1 , priority , self.MMICRxK , self.TK )
			if wepMIC is False:
				dot11wep.icv = 0 # NOTE: This only clears the ICV, not MICHAEL.
			
			# Transmit the packet.
			packet		= RadioTap()/dot11/dot11wep
			sendp( packet , iface=self.iface , verbose=False )
			
		except:
			raise
	
	def gk_handshake_2_2_aes( self , eapolMIC = True , eapolMICFlag = True , wepMIC = True , customFlaglist = None , addNonce = None , customRC = None , addData = None ):
		""" Group Key Handshake 2/2 (WPA).
		"""
		parameterList = 'eapolMIC=' + str(eapolMIC) + ',eapolMICFlag=' + str(eapolMICFlag) + ',wepMIC=' + str(wepMIC) + ',customFlaglist=' + str(customFlaglist) + ',addNonce=' + str(addNonce) + ',customRC=' + str(customRC) + ',addData=' + str(addData)
		self.logger.log( self.logger.TRANSMIT , 'EAPOL Group Key Handshake Message 2/2 AES (' + parameterList + ')')
		try:
			
			# Create an empty EAPOL WPA Key packet.
			packet 		= EAPOL( version=1 , type='EAPOL-Key' )/EAPOL_Key()/EAPOL_WPAKey()
			packetKey 	= packet.getlayer( EAPOL_WPAKey )
			flaglist	= ['HMAC_SHA1_AES','group','secure']
			flaglist.append( self.keyID )
			if eapolMICFlag is True:
				flaglist.append('mic')
			
			# Fill in the fields.
			if customFlaglist is not None:
				flaglist = customFlaglist
			packetKey.KeyInfo = self.__getKeyInformation( flaglist )
			if customRC is not None:
				if customRC == 'lower':	
					self.replayCounter -= 1
				elif customRC == 'higher':
					self.replayCounter += 1
			packetKey.ReplayCounter = self.replayCounter
			if addNonce is not None:
				if addNonce == 'supplicant':
					packetKey.Nonce = self.SNonce
				if addNonce == 'authenticator':
					packetKey.Nonce = self.ANonce
				if addNonce == 'random':
					packetKey.Nonce = binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
			if addData is not None:
				if addData == 'data':
					packetKey.WPAKeyLength 	= 32
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataNoLength':
					packetKey.WPAKeyLength 	= 0
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataShortLength':
					packetKey.WPAKeyLength 	= 16
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
				if addData == 'dataLongLength':
					packetKey.WPAKeyLength 	= 48
					packetKey.WPAKey 	= binascii.a2b_hex( os.urandom( 32 ).encode('hex') )
					
			# Calculate and add the MIC.
			if eapolMIC is True:
				mic = HMAC.new( self.KCK , msg=str( packet ) , digestmod=Crypto.Hash.SHA )
				packetKey.WPAKeyMIC = mic.digest()
			
			# Get the plaintext and generate the Logical-Link Control (LLC),
			# and Subnetwork Access Protocol (SNAP).
			plaintext 	= str( packet )
			llcSnap		= LLC( dsap=0xaa , ssap=0xaa , ctrl=0x03 )
			llcSnap	       /= SNAP( OUI=0x000000 , code=0x888e )
			plaintext	= str( llcSnap ) + plaintext
			
			# Generate the dot11 header and request the encapsulated dot11wep message.
			dot11		= Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , FCfield='wep+to-DS' , type='Data' , subtype=0 )
			dot11wep 	= self.handleAES.encapsulate( plaintext , self.TK , self.addr1 , self.addr2 , self.addr3 )
			if wepMIC is False:
				dot11wep.icv = 0 # NOTE/FIXME: This only clears part of the MIC, still making it incorrect though.
				
			# Transmit the packet.
			packet	= RadioTap()/dot11/dot11wep
			sendp( packet , iface=self.iface , verbose=False )
			
		except:
			raise
			
