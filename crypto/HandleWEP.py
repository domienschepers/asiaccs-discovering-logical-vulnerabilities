#!/usr/bin/env python2.7
from scapy.all import *
from Crypto.Cipher import ARC4
from crypto.util import calculateCRC , hasFCS , assertDot11FCS
from utility.util import getKeyID

class HandleWEP:
	""" Handles Wired equivalent privacy (WEP) encapsulation and decapsulation.
	"""

	######################################################################################
	### Initializer ######################################################################
	######################################################################################
	
	def __init__( self  ):
		""" Initializer.
		"""
		# Initialize the Initialization Vector (IV).
		self.iv = 0
		
	def __getIV( self ):
		""" Get the next Initialization Vector (IV) for encapsulation.
			FIXME: Bounds checking.
		"""
		self.iv += 1
		return self.iv
	
	######################################################################################
	### Encapsulation and Decapsulation ##################################################
	######################################################################################
		
	def encapsulate( self , plaintext , key ):
		""" Encapsulate WEP and return the encapsulated message.
			Ref. IEEE 802.11i specification; Wired equivalent privacy (WEP).
		"""
	
		# Generate the WEP parameters and the encryption key.
		iv 	= self.__getIV()
		iv	= '{:06x}'.format( iv ).decode('hex') # Parse int to three-octet IV.
		keyid 	= getKeyID( 0 )
		wepkey 	= iv + key
	
		# Encrypt the plaintext and calculate the ICV.
		arc4 	= ARC4.new( wepkey )
		wepdata = arc4.encrypt( plaintext )
		icv 	= calculateCRC( arc4 , plaintext )
	
		# Return the encapsulated WEP message.
		return Dot11WEP( iv=iv , keyid=keyid , wepdata=wepdata , icv=icv )

	def decapsulate( self , packet , key ):
		""" Decapsulate WEP and return the plaintext.
			Ref. IEEE 802.11i specification; Wired equivalent privacy (WEP).
		"""
		assert( packet.haslayer( Dot11WEP ) ), \
			'The given packet does not contain a Dot11WEP message (decapsulating WEP).'
		dot11wep = packet.getlayer( Dot11WEP )
	
		# Check if the Frame Check Sequence (FCS) flag is set in the Radiotap header.
		# If true assert the correctness of the FCS, and remove the FCS by shifting
		# the packet ICV and wepdata accordingly to keep consistency with non-FCS
		# implementations.
		radiotapFCSFlag	= hasFCS( packet )
		if radiotapFCSFlag is True:
			assertDot11FCS( packet , expectedFCS=dot11wep.icv )
			dot11wep.icv 		= int( dot11wep.wepdata[-4:].encode('hex') , 16 ) # Integer for consistency.
			dot11wep.wepdata 	= dot11wep.wepdata[:-4]
	
		# Generate the key and decrypt the ciphertext.
		key		= dot11wep.iv + key
		arc4 		= ARC4.new( key )
		plaintext	= arc4.decrypt( dot11wep.wepdata )
	
		# Decrypt the dot11wep ICV, and calculate the ICV over the plaintext.
		icv 		= '{0:0{1}x}'.format( dot11wep.icv , 8 ).decode('hex')
		icvReceived	= arc4.decrypt( icv )
		icvCalculated 	= struct.pack( '<L' , crc32( plaintext ) % (1<<32) )
	
		# Assert that the ICV's match.
		assert( icvReceived == icvCalculated ), \
			'The received ICV "0x%s" does not match the calculated ICV "0x%s".' \
			% ( icvReceived.encode('hex') , icvCalculated.encode('hex') )
	
		# Return the plaintext.
		return plaintext
		
