#!/usr/bin/env python2.7
from scapy.all import *
from crypto.util import getVendorInfo

class HandleManagement:
	""" Handle IEEE 802.11 Management Frames.
		FIXME: Validate the Frame Check Sequence (FCS).
	"""
		
	######################################################################################
	### Initializer ######################################################################
	######################################################################################
	
	def __init__( self , logger , iface , addr1 , addr2 , addr3 , ssid , channel ):
		""" Initializer.
		"""
		
		# System Settings
		self.logger	= logger
		
		# Default Parameters
		self.broadcast	= 'ff:ff:ff:ff:ff:ff'
		self.rates 	= '\x02\x04\x0b\x16\x0c\x12\x18\x24'	# Supported Rates
		self.esrates 	= '\x30\x48\x60\x6c'			# Extended Supported Rates
		
		# Parameters
		self.iface 	= iface
		self.addr1 	= addr1
		self.addr2	= addr2
		self.addr3 	= addr3
		self.ssid 	= ssid
		self.dsset 	= '{:02x}'.format( channel ).decode('hex')	# Current Channel
		
		# Optional handler for cryptographic encapsulation and decapsulation, key and 
		# challenge placeholder.
		self.handleWEP		= None
		self.wepKey		= None
		self.wepChallenge	= None
	
	def setWEPKey( self , key ):
		""" Set the key used in Wired equivalent privacy (WEP).
		"""
		self.wepKey = key
	
	def setCryptographicHandlers( self , wep = None  ):
		""" Set the cryptographic handlers for encapsulation and decapsulation.
		"""
		self.handleWEP = wep
	
	######################################################################################
	### Beacon ###########################################################################
	######################################################################################
	
	def beacon( self , packet ):
		""" Beacon.
		"""
		assert( packet.haslayer( Dot11Beacon ) ), \
			'The received packet does not contain a Beacon message.'
		self.logger.log( self.logger.RECEIVED , 'Beacon' )
	
	######################################################################################
	### Probe Request / Response #########################################################
	######################################################################################
		
	def probeRequest( self ):
		""" Probe Request.
			Transmits a probe request directly to the access point.
		"""
		self.logger.log( self.logger.TRANSMIT , 'Probe Request' )
		try:
		
			# Transmit the probe request.
			sendp(RadioTap()/
				Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.broadcast )/
				Dot11ProbeReq()/
				Dot11Elt( ID='SSID' 	, info=self.ssid )/
				Dot11Elt( ID='Rates' 	, info=self.rates )/
				Dot11Elt( ID='ESRates' 	, info=self.esrates )/
				Dot11Elt( ID='DSset' 	, info=self.dsset ), 
				iface=self.iface , verbose=False )
				
		except:
			raise
	
	def probeResponse( self , packet ):
		""" Probe Response.
		"""
		assert( packet.haslayer( Dot11ProbeResp ) ), \
			'The received packet does not contain a Probe Response message.'
		self.logger.log( self.logger.RECEIVED , 'Probe Response' )
	
	######################################################################################
	### Authentication Request / Response , and Deauthentication #########################
	######################################################################################
	
	def authenticationRequest( self , algorithm = 'open' , transmitWepChallenge = None ):
		""" Authentication Request.
			Transmits an authentication request to the access point.
		"""
		assert( algorithm in ('open','sharedkey') ), \
			'The algorithm "%s" is not supported.' % ( algorithm )
			
		if transmitWepChallenge is None or transmitWepChallenge is False:
			self.logger.log( self.logger.TRANSMIT , 'Authentication Request' )
			try:
				
				# Transmit the first (and only, for open networks) authentication request.
				sendp(RadioTap()/
					Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 )/
					Dot11Auth( algo=algorithm , seqnum=1 , status=0 ),
					iface=self.iface , verbose=False )
					
			except:
				raise
				
		elif transmitWepChallenge is True:
			assert( self.wepChallenge is not None ), \
				'No WEP Challenge Received'
				
			self.logger.log( self.logger.TRANSMIT , 'Authentication Request (With WEP Challenge)' )
			try:
			
				# Generate the plaintext.
				header 		= Dot11Auth( algo=algorithm , seqnum=3 , status=0 )
				header 	       /= Dot11Elt( ID='challenge' , len=128 )
				plaintext	= str( header ) + self.wepChallenge
				
				# Generate the dot11 header and request the encapsulated dot11wep message.
				dot11		= Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , FCfield='wep' , type=0x0 , subtype=0xb )
				dot11wep 	= self.handleWEP.encapsulate( plaintext , self.wepKey )
				
				# Transmit the authentication request.
				packet 		= RadioTap()/dot11/dot11wep
				sendp( packet , iface=self.iface , verbose=False )
				
			except:
				raise
			
	def authenticationResponse( self , packet ):
		""" Authentication Response.
		"""
		assert( packet.haslayer( Dot11Auth ) ), \
			'The received packet does not contain an Authentication message.'
		status 		= packet.getlayer( Dot11Auth ).status
		statusMessage 	= packet.getlayer( Dot11Auth ).get_field('status').i2repr( packet , status )
		# The WEP Challenge is represented by the ID number 16.
		if Dot11Elt in packet and packet[ Dot11Elt ].ID is 16:
			self.logger.log( self.logger.RECEIVED , 'Authentication Response (With WEP Challenge), status %s=%s.' % ( status , statusMessage ) )
			self.wepChallenge = packet[ Dot11Elt ].info
		else:
			if status == 0: self.logger.log( self.logger.RECEIVED , 'Authentication Response, status %s=%s.' % ( status , statusMessage ) )
			else:
				self.logger.log( self.logger.RECEIVED , 'Authentication Response, status %s=%s.' % ( status , statusMessage ) , error=True )
				raise Exception('The Authentication Response received an invalid Status Code (' + str(status) + '=' + statusMessage + ').')
	
	def deauthenticationRequest( self ):
		""" Deauthentication Request.
		"""
		self.logger.log( self.logger.TRANSMIT , 'Deauthentication' )
		try:
		
			# Transmit the deauthentication.
			sendp(RadioTap()/
				Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 )/
				Dot11Deauth( reason='auth-expired' ),
				iface=self.iface , verbose=False )
				
		except:
			raise
			
	def deauthenticationResponse( self , packet ):
		""" Deauthentication Reponse.
		"""
		assert( packet.haslayer( Dot11Deauth ) ), \
			'The received packet does not contain a Deauthentication message.'
		reason 		= packet.getlayer( Dot11Deauth ).reason
		reasonMessage 	= packet.getlayer( Dot11Deauth ).get_field('reason').i2repr( packet , reason )
		message		= 'Deauthentication with reason: %s (%d).' % ( reasonMessage , reason )
		self.logger.log( self.logger.RECEIVED , message )
		raise Exception( message )
		
	######################################################################################
	### Association Request / Response ###################################################
	######################################################################################
	
	def associationRequest( self , vendor = None ):
		""" Association Request.
			Transmits an association request to the access point.
			Vendor specific information (including cipher suit) may apply.
		"""
		if vendor is not None and vendor != 'NONE':
			self.logger.log( self.logger.TRANSMIT , 'Association Request (' + vendor + ')' )
			vendorInfo 	= getVendorInfo( type=vendor )
			vendorElt 	= Dot11Elt( ID='vendor' , info=vendorInfo )
		else:
			self.logger.log( self.logger.TRANSMIT , 'Association Request' )
			vendorElt = ''
		try:
		
			# Transmit the association request.
			# NOTE: The short-slot capability is only for our live settings.
			sendp(RadioTap()/
				Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr3 )/
				Dot11AssoReq( cap='short-slot' )/
				Dot11Elt( ID='SSID' 	, info=self.ssid )/
				Dot11Elt( ID='Rates' 	, info=self.rates )/
				Dot11Elt( ID='ESRates' 	, info=self.esrates )/
				Dot11Elt( ID='DSset' 	, info=self.dsset )/
				vendorElt,
				iface=self.iface , verbose=False )
				
		except:
			raise
	
	def associationResponse( self , packet ):
		""" Association Response.
		"""
		assert( packet.haslayer( Dot11AssoResp ) ), \
			'The received packet does not contain an Association Response message.'
		status = packet.getlayer( Dot11AssoResp ).status
		if status == 0:
			self.logger.log( self.logger.RECEIVED , 'Association Response, status %s.' % ( status ) )
		else:
			self.logger.log( self.logger.RECEIVED , 'Association Response, status %s.' % ( status ) , error=True )
			raise Exception('The Association Response received an invalid Status Code (' + str(status) + ').')
	
