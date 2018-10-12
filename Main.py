#!/usr/bin/env python2.7
import logging
logging.getLogger('scapy.runtime').setLevel( logging.ERROR )

from scapy import *
from functools import partial
import signal
from time import sleep

from HandleManagement import *
from HandleEAPoL import *
from HandleARP import *
from TraceManager import *

from utility.util import printTerminalLine
from utility.Logger import *

from crypto.HandleWEP import *
from crypto.HandleTKIP import *
from crypto.HandleAES import *

class Main:
	""" Main.
	"""
	
	def __init__( self ):
		""" Initializer.
		"""
		
		# Network Settings.
		self.iface 		= None
		self.addr1 		= None 	# Destination
		self.addr2 		= None 	# Source
		self.addr3 		= None	# Basic Service Set ID (BSSID)
		self.ssid 		= None
		self.channel		= None
		self.wepKey		= None
		self.passphrase		= None
		self.arpIpSource	= None
		self.arpIpDestination	= None
		self.__initNetworkSettings()
		
		# Initialize the Operating System.
		self.__initOperatingSystem()
		
		# Signal Settings for the timeout interval (in seconds).
		signal.signal( signal.SIGALRM , self.__signal_handler )
		self.signalInterval = 0.4
		
		# Logger, and Handlers for management, EAPoL and ICMP frames.
		self.logger		= Logger( filename='log.txt' , terminal=True )
		self.handleMgmt 	= HandleManagement( self.logger , self.iface , self.addr1 , self.addr2 , self.addr3 , self.ssid , self.channel )
		self.handleEAPoL 	= HandleEAPoL( self.logger , self.iface , self.addr1 , self.addr2 , self.addr3 , self.ssid )
		self.handleARP		= HandleARP( self.logger , self.iface , self.addr1 , self.addr2 , self.addr3 , self.arpIpSource , self.arpIpDestination )
		
		# Set the keys and passphrases used in the above handlers.
		self.handleMgmt.setWEPKey( self.wepKey )
		self.handleEAPoL.setPassphrase( self.passphrase )
		
		# Cryptographic handlers for encapsulation and decapsulation.
		self.handleWEP	= HandleWEP()
		self.handleTKIP	= HandleTKIP()
		self.handleAES	= HandleAES()
		
		# Set the cryptographic handlers.
		self.handleMgmt.setCryptographicHandlers( wep=self.handleWEP )
		self.handleEAPoL.setCryptographicHandlers( tkip=self.handleTKIP , aes=self.handleAES )
		self.handleARP.setCryptographicHandlers( wep=self.handleWEP , tkip=self.handleTKIP , aes=self.handleAES )
		
		# Traces holding the list of all traces, and its Trace Manager.
		self.traceManager 	= TraceManager( self.handleMgmt , self.handleEAPoL )
		self.traces		= self.traceManager.getTraces()
		
		# Trace and helpers, holding information about the trace under test.
		self.trace 		= None
		self.tracePosition	= None
		self.traceBeaconed	= False
		self.traceFinished	= False
		
	def printResults( self ):
		""" Print the obtained results.
		"""
		self.traceManager.printResults()
	
	def __initOperatingSystem( self ):
		""" Initialize requirements in the Operating System (OS).
			NOTE: 	It might be necessary to restart the interface with:
				ifconfig self.iface down; ifconfig self.iface up
		"""
		# Set the requested channel on the interface.
		os.system( 'iwconfig ' + self.iface + ' channel ' + str(self.channel) )
	
	def __initNetworkSettings( self ):
		""" Initialize the network settings; select the simulated or one of the physical
			routers. 
		"""
		#self.__setSettingsSimulation()
		self.__setSettingsForSomeRouter()
		
	def __setSettingsSimulation( self ):
		self.iface 		= 'wlan1'
		self.addr1 		= '02:00:00:00:00:00'	# Destination MAC
		self.addr2 		= '02:00:00:00:01:00'	# Source MAC
		self.addr3 		= '02:00:00:00:00:00'	# Basic Service Set ID (BSSID)
		self.ssid 		= 'TEST_NETWORK'
		self.channel		= 1
		self.wepKey		= 'abcde'
		self.passphrase		= 'abcdefgh'
		self.arpIpSource	= '192.168.1.2' 	# Within the same subnet of the destination.
		self.arpIpDestination	= '192.168.1.1'
	
	def __setSettingsForSomeRouter( self ):
		self.iface 		= 'wlan0'
		self.addr1 		= 'aa:bb:cc:dd:ee:ff' 	# Destination MAC
		self.addr2 		= 'ff:ee:dd:cc:bb:aa' 	# Source MAC
		self.addr3 		= self.addr1 		# Basic Service Set ID (BSSID)
		self.ssid 		= 'TEST_NETWORK'
		self.channel		= 1
		self.passphrase		= 'abcdefgh'
		self.arpIpSource	= '192.168.1.2'		# Within the same subnet of the destination.
		self.arpIpDestination	= '192.168.1.1'
		
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
		
	def run( self ):
		""" Run all available traces.
		"""
		assert( self.traces is not None ), \
			'There are no traces available to be executed.'
		printTerminalLine( '=' )
		for x , trace in enumerate( self.traces ):
			self.__traceRun( trace[0] , trace[1] )
			if x < len( self.traces ) - 1:
				printTerminalLine( '-' )
	
	def __traceRun( self , trace , validationType ):
		""" Run the given trace, from now on known as the trace under test.
			Note: 	The current implementation assumes that the first message in the trace
				under test waits for a message to be received. Most commonly this will
				be a beacon frame from the access point.
		"""
		assert( trace is not None and trace is not [] ), \
			'There is no trace given, or it is empty, and can therefore not be executed.'
		self.trace 		= trace
		self.tracePosition 	= 0
		self.traceBeaconed 	= False
		self.traceFinished	= False
		
		# Run the trace and upon completion validate the connection. If either of them
		# fails the exception handler will catch the error message and mark the trace as
		# failed. If the connection is validated positively, the trace is marked as
		# success.
		# FIXME: http://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python
		try:
			self.logger.log( self.logger.ACTION , 'Starting Trace...' )
			sniff( iface=self.iface , lfilter=self.__traceFilter, stop_filter=self.__traceStopCondition , prn=self.__traceHandler )
			signal.setitimer( signal.ITIMER_REAL , 0.0 ) # Reset the timer.
			if validationType is None:
				raise Exception( 'No Validation Type was given.' )
			sleep( 100.00 / 1000.00 ); # Sleep for 100ms before validation.
			self.__traceValidateConnection( validationType )
			self.traceManager.markTrace( type='SUCCESS' , trace=self.trace , validation=validationType )
			
		# Catch exceptions; log the message and mark the trace as failed.
		except Exception , message:
			self.logger.log( self.logger.EXCEPTION , str(message) )
			self.traceManager.markTrace( type='FAILURE' , trace=self.trace , validation=validationType )
			
		# Reset the connection state with the access point.
		self.__traceReset()
		
	def __traceFilter( self , packet ):
		""" Filters all sniffed packets and decides if they should be passed to the
			handler. Returns False if the packet should be discarded, True otherwise.
		"""
		# Check the packet for a Dot11 layer.
		if not packet.haslayer( Dot11 ):
			return False
		
		# Check if the packet is whitelisted.
		messages = [	( 0 ,  1 ), # Association Response
				( 0 ,  5 ), # Probe Response
				( 0 ,  8 ), # Beacon
				( 0 , 11 ), # Authentication
				( 0 , 12 ), # Deauthentication
				( 2 ,  0 )] # Data
		if ( packet.type , packet.subtype ) not in messages:
			return False
		
		# Check if the packet is a beacon; ignore the second and later occurrences.
		if packet.type == 0 and packet.subtype == 8:
			if self.traceBeaconed is True:
				return False
			self.traceBeaconed = True
		else:
			# Check if we are the intended receivers of the packet.
			if self.__isPacketIntendedForUs( packet ) is False:
				return False
		
		# Could not discard the packet in the above checks; so we are ready to pass it on
		# to the handler by returning True.
		return True
	
	def __traceStopCondition( self , packet ):
		""" Checks if the trace under test is finished.
		"""
		return self.traceFinished
	
	def __traceHandler( self , packet ):
		""" Handles the received packets by passing them to the next function in the
			trace. Next, it checks if new messages have to be transmitted.
		"""
		# Reset the signal timer upon receipt of a new message.
		signal.setitimer( signal.ITIMER_REAL , 0.0 )
		
		# Received a new message; pass the packet along to the respective trace function.
		# Check if it is an unexpected deauthentication.
		if packet.haslayer( Dot11Deauth ):
			nextFunctionName = self.trace[ self.tracePosition ][1].func.func_name
			if nextFunctionName != 'deauthenticationResponse':
				self.logger.log( self.logger.ERROR , 'Expected ' + nextFunctionName + ', received deauthenticationResponse...' )
				self.handleMgmt.deauthenticationResponse( packet ) # Raises exception.
		# We are good... continue.
		self.trace[ self.tracePosition ][1]( packet=packet ) # Receive function call.
		self.tracePosition += 1
		if self.tracePosition == len( self.trace ):
			self.traceFinished = True
			return
		
		# If another message is to be received next, we must set the timer.
		if self.trace[ self.tracePosition ][0] == 'RECEIVE':
			signal.setitimer( signal.ITIMER_REAL , self.signalInterval )
		
		# Possibly, but not necessarily, the next message(s) have to be transmitted. After
		# transmitting a new message the signal timer has to be restarted.
		while( self.trace[ self.tracePosition ][0] == 'TRANSMIT' ):
			self.trace[ self.tracePosition ][1]() # Transmit function call.
			signal.setitimer( signal.ITIMER_REAL , self.signalInterval )
			self.tracePosition += 1
			if self.tracePosition == len( self.trace ):
				self.traceFinished = True
				return
		
	def __traceValidateConnection( self , validationType ):
		""" Validate the connection at the end of a "successful" trace. The handler raises
			an exception when the trace realised an unsuccessful connection.
		"""
		self.logger.log( self.logger.ACTION , 'Validating Connection with ARP...' )
		
		# Push the keys to the ARP Handler.
		self.handleARP.setKeys( wepkey=self.wepKey , TK=self.handleEAPoL.TK , MMICTxK=self.handleEAPoL.MMICTxK , MMICRxK=self.handleEAPoL.MMICRxK )
		
		# Transmit an ARP request to the access point to validate a successful connection.
		# Throws a timeout, or an exception due to a disassociation, when unsuccessful.
		self.handleARP.validate( validationType )
		
	def __traceReset( self ):
		""" Reset the connection state with the access point by transmitting a
			deauthentication message.
		"""
		self.logger.log( self.logger.ACTION , 'Resetting...' )
		
		# Reset the connection state with the access point, and remove the trace under 
		# test.
		self.handleMgmt.deauthenticationRequest()
		self.trace = None
		
##########################################################################################
##########################################################################################
#### Main Program ########################################################################
##########################################################################################
##########################################################################################
main = Main()
main.run()
main.printResults()
