#!/usr/bin/env python2.7
from scapy.all import *
import signal
import binascii

class HandleARP:
	""" Handle Address Resolution Protocol (ARP) messages.
	"""
		
	######################################################################################
	### Initializer ######################################################################
	######################################################################################
	
	def __init__( self , logger , iface , addr1 , addr2 , addr3 , ipSource , ipDestination ):
		""" Initializer.
		"""
		
		# System Settings.
		self.logger		= logger
		
		# Parameters.
		self.iface 		= iface
		self.addr1 		= addr1 # Destination
		self.addr2		= addr2 # Source
		self.addr3 		= addr3 # Basic Service Set Identifier
		self.ipSource		= ipSource
		self.ipDestination	= ipDestination
		
		# Signal Settings for the timeout interval (in seconds).
		signal.signal( signal.SIGALRM , self.__signal_handler )
		self.signalInterval	= 0.4
		
		# Initialize the ARP Request and Response handlers.
		self.arpRequest 	= self.__arpRequest
		self.arpResponse 	= self.__arpResponse
		
		# Encryption Keys.
		self.wepkey	= None
		self.TK 	= None
		self.MMICTxK 	= None
		self.MMICRxK 	= None
	
	def setCryptographicHandlers( self , wep = None , tkip = None , aes = None ):
		""" Set the cryptographic handlers for encapsulation and decapsulation.
		"""
		self.handleWEP 	= wep
		self.handleTKIP = tkip
		self.handleAES 	= aes
			
	def setKeys( self , wepkey = None , TK = None , MMICTxK = None , MMICRxK = None ):
		""" Set the keys used for encapsulation and decapsulation of ARP messages.
		"""
		self.wepkey	= wepkey
		self.TK 	= TK
		self.MMICTxK 	= MMICTxK
		self.MMICRxK 	= MMICRxK
		
	######################################################################################
	### Address Resolution Protocol (ARP) ################################################
	######################################################################################
	
	# ------------------------------------------------------------------------------------
	# --- Address Resolution Protocol (ARP) Request --------------------------------------
	# ------------------------------------------------------------------------------------
	
	def __getARPRequestMessage( self ):
		""" Generate the ARP Request message.
		"""
		
		# Generate the message headers.
		llc	= LLC()
		snap	= SNAP()
		arp	= ARP( op='who-has' , hwsrc=self.addr2 , psrc=self.ipSource , hwdst=self.addr1 , pdst=self.ipDestination )

		# Return the ARP Request message.
		return llc/snap/arp
	
	def __arpRequest( self ):
		""" ARP Request.
		"""
		self.logger.log( self.logger.TRANSMIT , 'ARP Request' )
		
		# Retrieve the ARP Request message and generate the headers.
		message = self.__getARPRequestMessage()
		dot11 	= Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , type='Data' , subtype=0 , FCfield='to-DS' )

		# Transmit the packet.
		packet 	= RadioTap()/dot11/message
		sendp( packet , iface=self.iface , verbose=False )
		
	def __arpRequestWEP( self ):
		""" Handle an ARP Request encapsulated in WEP.
		"""
		self.logger.log( self.logger.TRANSMIT , 'ARP Request (WEP)' )
		
		# Retrieve the ARP Request message and generate the headers.
		plaintext	= str( self.__getARPRequestMessage() )
		dot11		= Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , FCfield='wep+to-DS' , type='Data' , subtype=0 )
		dot11wep 	= self.handleWEP.encapsulate( plaintext , self.wepkey )
		
		# Transmit the packet.
		packet = RadioTap()/dot11/dot11wep
		sendp( packet , iface=self.iface , verbose=False )
		
	def __arpRequestTKIP( self ):
		""" Handle an ARP Request encapsulated in TKIP.
		"""
		self.logger.log( self.logger.TRANSMIT , 'ARP Request (TKIP)' )
		
		# Addresses and priority settings.
		addr1 		= binascii.a2b_hex( self.addr1.replace( ':' , '' ) )
		addr2 		= binascii.a2b_hex( self.addr2.replace( ':' , '' ) )
		priority	= 0
		
		# Retrieve the ARP Request message and generate the headers.
		plaintext	= str( self.__getARPRequestMessage() )
		dot11		= Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , FCfield='wep+to-DS' , type='Data' , subtype=0 )
		dot11wep 	= self.handleTKIP.encapsulate( plaintext , addr2 , addr1 , priority , self.MMICRxK , self.TK )

		# Transmit the packet.
		packet = RadioTap()/dot11/dot11wep
		sendp( packet , iface=self.iface , verbose=False )
		
	def __arpRequestAES( self ):
		""" Handle an ARP Request encapsulated in AES.
		"""
		self.logger.log( self.logger.TRANSMIT , 'ARP Request (AES)' )
		
		# Retrieve the ARP Request message and generate the headers.
		plaintext	= str( self.__getARPRequestMessage() )
		dot11 		= Dot11( addr1=self.addr1 , addr2=self.addr2 , addr3=self.addr1 , FCfield=0x41 , type=0x2 , subtype=0x0 )
		dot11wep 	= self.handleAES.encapsulate( plaintext , self.TK , self.addr1 , self.addr2 , self.addr3 )
		
		# Transmit the packet.
		packet = RadioTap()/dot11/dot11wep
		sendp( packet , iface=self.iface , verbose=False )
	
	# ------------------------------------------------------------------------------------
	# --- Address Resolution Protocol (ARP) Response -------------------------------------
	# ------------------------------------------------------------------------------------
		
	def __arpResponse( self , packet , decapsulatedFrom = None ):
		""" ARP Response.
		"""
		assert( packet.haslayer( ARP ) ), \
			'The received packet does not contain an ARP message.'
		
		# Asserts on the correctness of the ARP message.
		arp 	= packet.getlayer( ARP )
		name 	= arp.get_field('op').i2repr( packet , arp.op )
		assert( name == 'is-at' ), \
			'The ARP message has the wrong operation (%s).' % ( name )
		assert( arp.hwdst == self.addr2 ), \
			'The ARP message has the wrong MAC destination address (%s).' % ( arp.hwdst )
		assert( arp.psrc == self.ipDestination ), \
			'The ARP message has the wrong IP source address (%s).' % ( arp.psrc )
		assert( arp.pdst == self.ipSource ), \
			'The ARP message has the wrong IP destination address (%s).' % ( arp.pdst )
		
		# Log that an ARP Response message was received.
		message = 'ARP Response'
		if decapsulatedFrom is not None:
			message += ' (' + decapsulatedFrom + ')'
		self.logger.log( self.logger.RECEIVED , message )
		
	def __arpResponseWEP( self , packet ):
		""" Handle an ARP Response encapsulated in WEP.
		"""
		# Decapsulate the packet and rebuild the ARP message from the plaintext.
		plaintext 	= self.handleWEP.decapsulate( packet , self.wepkey )
		new_packet 	= LLC()/SNAP()/ARP()
		new_packet 	= new_packet.__class__( plaintext )
		
		# Let the regular handler take further care of this.
		self.__arpResponse( new_packet , decapsulatedFrom='WEP' )
	
	def __arpResponseTKIP( self , packet ):
		""" Handle an ARP Response encapsulated in TKIP.
		"""
		# Decapsulate the packet and rebuild the ARP message from the plaintext.
		plaintext 	= self.handleTKIP.decapsulate( packet , self.TK , self.MMICTxK )
		new_packet 	= LLC()/SNAP()/ARP()
		new_packet 	= new_packet.__class__( plaintext )
		
		# Let the regular handler take further care of this.
		self.__arpResponse( new_packet , decapsulatedFrom='TKIP' )
		
	def __arpResponseAES( self , packet ):
		""" Handle an ARP Response encapsulated in AES.
		"""
		# Decapsulate the packet and rebuild the ARP message from the plaintext.
		plaintext 	= self.handleAES.decapsulate( packet , self.TK )
		new_packet 	= LLC()/SNAP()/ARP()
		new_packet 	= new_packet.__class__( plaintext )
		
		# Let the regular handler take further care of this.
		self.__arpResponse( new_packet , decapsulatedFrom='AES' )
		
	######################################################################################
	### Handlers for executing the ARP Request and Response messages #####################
	######################################################################################
		
	def __signal_handler( self , signum , frame ):
		""" Handler for signal events.
		"""
		raise Exception("Timeout.")
	
	def __isPacketIntendedForUs( self , packet ):
		""" Check if we are the intended receivers of the packet by comparing the MAC
			addresses in the given packet against our own MAC addresses.
		"""
		# The packet destination address (addr1) must equal our source address (addr2).
		if packet.addr1 != self.addr2: return False
		# The packet source address (addr2) must equal our destination address (addr1).
		if packet.addr2 != self.addr1: return False
		return True
		
	def validate( self , validationType ):
		""" Validates the successful connection by transmitting an ARP Request.
		"""
		assert( validationType in ('OPEN','WEP','TKIP','AES') ), \
			'The Validation Type "%s" is unsupported.' % ( validationType )
		self.requested	= False
		self.finished 	= False
		
		# Adjust the ARP Request and Response handlers to the Validation Type.
		if validationType == 'WEP':
			self.arpRequest 	= self.__arpRequestWEP
			self.arpResponse 	= self.__arpResponseWEP
		if validationType == 'TKIP':
			self.arpRequest 	= self.__arpRequestTKIP
			self.arpResponse 	= self.__arpResponseTKIP
		if validationType == 'AES':
			self.arpRequest 	= self.__arpRequestAES
			self.arpResponse 	= self.__arpResponseAES
		
		# Start the sniffer with respective filter, stop condition and handler.
		sniff( iface=self.iface , lfilter=self.__traceFilter , stop_filter=self.__stopCondition , prn=self.__arpHandler )
		
	def __traceFilter( self , packet ):
		""" Filters all sniffed packets and decides if they should be passed to the
			handler. Returns False if the packet should be discarded, True otherwise.
		"""
		# Check the packet for a Dot11 layer.
		if not packet.haslayer( Dot11 ):
			return False
		
		# Check if the packet is whitelisted; beacons are allowed to trigger the
		# transmission of the ARP Request. 
		messages = [	( 0 ,  8 ), # Beacon
				( 2 ,  0 )] # Data
		if ( packet.type , packet.subtype ) not in messages:
			return False
		
		# Could not discard the packet in the above checks; so we are ready to pass it on
		# to the handler by returning True.
		return True
	
	def __stopCondition( self , packet ):
		""" Checks if an ARP Response has been received.
		"""
		return self.finished
	
	def __arpHandler( self , packet ):
		""" Handles the received messages.
		"""
		
		# Transmit the ARP Request and start the timer.
		if self.requested is False:
			self.requested = True
			self.arpRequest()
			signal.setitimer( signal.ITIMER_REAL , self.signalInterval )
			return
		
		# Handle the ARP Response message if it is intended for us.
		if self.__isPacketIntendedForUs( packet ) is True:
			signal.setitimer( signal.ITIMER_REAL , 0.0 )
			self.arpResponse( packet )
			self.finished = True
			
