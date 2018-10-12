#!/usr/bin/env python2.7
from functools import partial
import os
from utility.util import printTerminalLine
from copy import copy
from itertools import combinations

class TraceManager:
	""" Trace Manager.
		NOTE: Traces must start by receiving some beacon.
	"""
	
	def __init__( self , handleMgmt , handleEAPoL ):
		""" Initializer.
		"""
		
		# Handlers for Management and EAPoL Frames.
		self.handleMgmt 	= handleMgmt
		self.handleEAPoL 	= handleEAPoL
		
		# Lists of traces.
		self.listGenerated	= []	# All the generated traces.
		self.listSuccess	= []	# Traces that were marked   successful.
		self.listFailure	= []	# Traces that were marked unsuccessful.
		self.listWhitelisted	= []	# Traces that are whitelisted (i.e. valid).
	
		# Settings.
		self.printCustomFlaglist = False
	
	def getTraces( self ):
		""" Retrieve the set of traces to be tested.
		"""
		# Select a base-trace and add it to the trace lists. Options are: __getTraceOpen(),
		# __getTraceWEP() , __getTraceTKIP() , and __getTraceAES().
		trace 			= self.__getTraceAES()
		#traceSwitching 	= self.__getTraceTKIP()
		self.listGenerated.append( trace )
		self.listWhitelisted.append( trace )

		# Generate new traces based on the base-trace.
		#self.listGenerated += self.__generateInsertion( trace[0] , trace[1] )
		#self.listGenerated += self.__generateSkipped( trace[0] , trace[1] )
		#self.listGenerated += self.__generatedRetransmission( trace[0] , trace[1] )
		#self.listGenerated += self.__generateWepMIC( trace[0] , trace[1] )
		#self.listGenerated += self.__generateEapolMIC( trace[0] , trace[1] )
		#self.listGenerated += self.__generateSwitchCryptoTrace( trace[0] , 'AES' , traceSwitching[0] )
		#self.listGenerated += self.__generateSwitchCryptoTrace( trace[0] , 'TKIP' , traceSwitching[0] )
		#self.listGenerated += self.__generateSwitchCryptoMsg( trace[0] , 'AES' , traceSwitching[0] )
		#self.listGenerated += self.__generateSwitchCryptoMsg( trace[0] , 'TKIP' , traceSwitching[0] )
		#self.listGenerated += self.__generateBruteForceFlags( trace[0] , trace[1] )
		#self.listGenerated += self.__generateVendorElements( trace[0] , trace[1] )
		#self.listGenerated += self.__generateNonces( trace[0] , trace[1] )
		#self.listGenerated += self.__generateReplayCounter( trace[0] , trace[1] )
		#self.listGenerated += self.__generateRandomData( trace[0] , trace[1] )
		#self.listGenerated += self.__generateTKIPMICFailure( trace[0] )
		
		# Return the list of generated traces.
		return self.listGenerated
	
	def markTrace( self , type , trace , validation ):
		""" Mark traces as succesfull or failure.
		"""
		assert( type in ('SUCCESS','FAILURE') ), \
			'The given trace type "%s" is not recognized.' % ( type )
		if type is 'SUCCESS':
			self.listSuccess.append( ( trace , validation ) )
		if type is 'FAILURE':
			self.listFailure.append( ( trace , validation ) )
	
	######################################################################################
	### Print Results ####################################################################
	######################################################################################
			
	def printResults( self ):
		""" Print an overview of the successful traces.
		"""
		numGenerated	= len( self.listGenerated )
		numSuccess 	= len( self.listSuccess )
		numFailure 	= len( self.listFailure )
		numTotal	= numSuccess + numFailure
		assert( numGenerated == numTotal ), \
			'Internal Error; Only %d out of %d traces are marked as success or failure.' \
				% ( numTotal , numGenerated )
		
		# Print a brief overview of successful and failed traces.
		printTerminalLine( '=' )
		print 'Traces Success:\t%d/%d' % ( numSuccess , numGenerated )
		print 'Traces Failure:\t%d/%d' % ( numFailure , numGenerated )
		printTerminalLine( '=' )
		
		# Print every successful trace.
		for i , trace in enumerate( self.listSuccess ):
			if self.__isWhitelisted( trace ) is True:
				self.__printTrace( trace , whitelisted=True )
			else:
				self.__printTrace( trace )
			if i < numSuccess-1:
				printTerminalLine( '-' )
		printTerminalLine( '=' )
		if self.printCustomFlaglist is True:
			self.__printCustomFlaglist()
		
	def __printTrace( self , trace , whitelisted = False ):
		""" Print all messages of the given trace, followed by its validation type.
		""" 
		validationType	= trace[1]
		trace 		= trace[0]
		for index , message in enumerate( trace ):
			type 			= message[0]
			partialFunction		= message[1]
			partialFunctionName	= partialFunction.func.func_name
			partialFunctionKeywords	= partialFunction.keywords
			
			# Print the messages of the trace in the appropriate color.
			if whitelisted is True: print '\033[92m',
			else: print '\033[93m',
			print '%02d \t%s \t%s' % ( index , type , partialFunctionName ),
			if partialFunctionKeywords is not None:
				print partialFunctionKeywords,
			print '\033[0m'
			
		# Print the validation type.
		print ' %s Validation' % ( validationType )
	
	def __isWhitelisted( self , trace ):
		""" Check if the given trace is whitelisted.
		"""	
		for traceWhitelisted in self.listWhitelisted:
			if traceWhitelisted[0] == trace[0]:
				return True
		return False
	
	def __printCustomFlaglist( self ):
		""" Print an overview of all the succeeded flaglists.
		"""
		functionList 	= ( 'fw_handshake_2_4_tkip' , 'fw_handshake_4_4_tkip' , 'gk_handshake_2_2_tkip' )
		functionList   += ( 'fw_handshake_2_4_aes'  , 'fw_handshake_4_4_aes'  , 'gk_handshake_2_2_aes' )
		printTerminalLine( '=' )
		for trace in self.listSuccess:
			for message in trace[0]:
				partialFunction		= message[1]
				partialFunctionName	= partialFunction.func.func_name
				partialFunctionKeywords	= partialFunction.keywords
				if partialFunctionName in functionList and partialFunctionKeywords is not None:
					if 'customFlaglist' in partialFunctionKeywords.keys():
						print partialFunctionName , partialFunctionKeywords['customFlaglist']
		printTerminalLine( '=' )
		
	######################################################################################
	### Trace Generation Algorithms ######################################################
	######################################################################################
	
	def __generateInsertion( self , trace , validationType ):
		""" Generate traces where we insert messages at all possible positions.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces 		= []
		transmitTuples 	= self.__getTransmitTuples( trace , trimProbe=True )
				
		# Retrieve the transmit positions.
		transmitPositions = []
		for x , message in enumerate( trace ):
			if message[0] == 'TRANSMIT':
				transmitPositions.append( x )
						
		# Iterate over all found positions.
		for pos in transmitPositions:
			# Generate len(transmitTuples) traces for each position.
			for x in xrange( len(transmitTuples) ):
				newTrace = copy( trace )
				newTrace.insert( pos 	, transmitTuples[x][0] )
				newTrace.insert( pos+1 	, transmitTuples[x][1] )
				traces.append( ( newTrace , validationType ) )
		
		# Assert that we have generated the expected number of traces.
		assert( len(transmitTuples)*len(transmitPositions) == len(traces) ), \
			'Internal error; invalid number of generated traces.'
		return self.__removeDuplicates( traces , trace )
	
	def __generateSkipped( self , trace , validationType ):
		""" Generate a set of traces that skips a TRANSMIT message and the following
			RECEIVE messages. The resulting set has a length equal to the number of
			TRANSMIT messages in the original trace. 
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		
		# Count the number of TRANSMIT-messages in the trace.
		numTransmits = 0
		for message in trace:
			if message[0] == 'TRANSMIT':
				numTransmits += 1

		# Generate a trace where the x'th TRANSMIT-message is skipped.
		for x in xrange( numTransmits ):
			newTrace = copy( trace )
			
			# Remove the respective TRANSMIT-messages.
			transmitCounter = 0
			for index , message in enumerate( newTrace ):
				if message[0] == 'TRANSMIT':
					if transmitCounter == x:
						newTrace.remove( message )
						break
					transmitCounter += 1
			
			# Given the previous index, remove the corresponding RECEIVE-messages.
			while( index < len(newTrace) and newTrace[index][0] == 'RECEIVE' ):
				del newTrace[ index ]
			
			# Append the resulting trace.
			traces.append( ( newTrace , validationType ) )
		
		# Assert that we have generated the expected number of traces.
		assert( len(traces) == numTransmits ), \
			'Internal error; invalid number of generated traces.'
		return traces
	
	def __generatedRetransmission( self , trace , validationType ):
		""" Generate traces with retransmissions.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		
		# Count the number of TRANSMIT-messages in the trace.
		numTransmits = 0
		for message in trace:
			if message[0] == 'TRANSMIT':
				numTransmits += 1
				
		# Generate a trace where the x+1'th TRANSMIT-message is replaced by the x'th.
		for x in range( 1 , numTransmits ):
			newTrace = copy( trace )
		
			# Iterate over the respective TRANSMIT-messages. Find and save the x-1'th
			# message, then replace the x'th message.
			transmitCounter = 0
			for index , message in enumerate( newTrace ):
				if message[0] == 'TRANSMIT':
					if transmitCounter == x-1:
						savedMessage = message
					if transmitCounter == x:
						newTrace[index] = savedMessage
						break
					transmitCounter += 1
					
			# Append the resulting trace.
			traces.append( ( newTrace , validationType ) )
			
		# Assert that we have generated the expected number of traces.
		assert( len(traces) == numTransmits-1 ), \
			'Internal error; invalid number of generated traces.'
		return traces
	
	def __generateWepMIC( self , trace , validationType ):
		""" Generate traces where the Dot11WEP MIC has invalid settings.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		
		# Generate traces where the frame MIC is invalid.
		functionList = ( 'gk_handshake_2_2_tkip' , 'gk_handshake_2_2_aes' )
		for selectedFunction in functionList:
			newTrace = copy( trace )
			
			# Iterate the messages in the trace and find one that matches the selected
			# function, and update its keywords.
			for x , message in enumerate( newTrace ):
				currentFunction = message[1].func.func_name
				if currentFunction == selectedFunction:
					if message[1].keywords is None:
						newFunction = partial( message[1].func , wepMIC=False )
						newTrace[x] = ( message[0] , newFunction )
					else:
						raise Exception('Operation Not Supported')
					# Append the resulting trace.
					traces.append( ( newTrace , validationType ) )
					break
				
		# Assert that we have generated the expected number of traces.
		assert( len(traces) == 1 ), \
			'Internal error; invalid number of generated traces.'
		return traces
		
	def __generateEapolMIC( self , trace , validationType ):
		""" Generate traces where the EAPoL MIC has invalid settings.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		
		# Generate traces where the EAPoL MIC is invalid.
		functionList 	= ( 'fw_handshake_2_4_tkip' , 'fw_handshake_4_4_tkip' , 'gk_handshake_2_2_tkip' )
		functionList   += ( 'fw_handshake_2_4_aes'  , 'fw_handshake_4_4_aes'  , 'gk_handshake_2_2_aes' )
		for selectedFunction in functionList:
			newTraceA = copy( trace )
			newTraceB = copy( trace )
			newTraceC = copy( trace )
			
			# Iterate the messages in the trace and find one that matches the selected
			# function, and update its keywords.
			for x , message in enumerate( newTraceA ):
				currentFunction = message[1].func.func_name
				if currentFunction == selectedFunction:
					if message[1].keywords is None:
						newTraceA[x] = ( message[0] , partial( message[1].func , eapolMIC=False , eapolMICFlag=True ) )
						newTraceB[x] = ( message[0] , partial( message[1].func , eapolMIC=True , eapolMICFlag=False ) )
						newTraceC[x] = ( message[0] , partial( message[1].func , eapolMIC=False , eapolMICFlag=False ) )
					else:
						newTraceA[x] = ( message[0] , partial( message[1].func , eapolMIC=False , eapolMICFlag=True ) )
						newTraceB[x] = ( message[0] , partial( message[1].func , eapolMIC=True , eapolMICFlag=False ) )
						newTraceC[x] = ( message[0] , partial( message[1].func , eapolMIC=False , eapolMICFlag=False ) )
						newTraceA[x][1].keywords.update( message[1].keywords )
						newTraceB[x][1].keywords.update( message[1].keywords )
						newTraceC[x][1].keywords.update( message[1].keywords )
					# Append the resulting trace.
					traces.append( (newTraceA,validationType) )
					traces.append( (newTraceB,validationType) )
					traces.append( (newTraceC,validationType) )
				
		# Assert that we have generated the expected number of traces.
		assert( len(traces) == 9 ), \
			'Internal error; invalid number of generated traces.'
		return traces
	
	def __generateSwitchCryptoTrace( self , trace , validationType , traceSwitch ):
		""" Switch from a trace to the traceSwitch at every TRANSMIT-position.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		
		# Retrieve the transmit positions.
		transmitPositions = []
		for x , message in enumerate( trace ):
			if message[0] == 'TRANSMIT':
				transmitPositions.append( x )
		
		# Swap traces at every transmit position.
		for pos in transmitPositions:
			newTrace = copy( trace )
			newTrace = newTrace[:pos] + traceSwitch[pos:]
			traces.append( ( newTrace , validationType ) )
		
		# Assert that we have generated the expected number of traces.
		assert( len(traces) == len(transmitPositions) ), \
			'Internal error; invalid number of generated traces.'
		return self.__removeDuplicates( traces , trace )
		
	def __generateSwitchCryptoMsg( self , trace , validationType , traceSwitch ):
		""" Switch from a trace to the traceSwitch at every TRANSMIT-position.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		assert( len( trace ) == len ( traceSwitch ) ), \
			'The length of the given traces does not match.'
		traces = []
		
		# Retrieve the transmit positions.
		transmitPositions = []
		for x , message in enumerate( trace ):
			if message[0] == 'TRANSMIT':
				transmitPositions.append( x )
		
		# Swap traces at every transmit position.
		for pos in transmitPositions:
			newTrace = copy( trace )
			newTrace[pos] = traceSwitch[pos]
			traces.append( ( newTrace , validationType ) )
		
		# Assert that we have generated the expected number of traces.
		assert( len(traces) == len(transmitPositions) ), \
			'Internal error; invalid number of generated traces.'
		return self.__removeDuplicates( traces , trace )
	
	def __generateBruteForceFlags( self , trace , validationType ):
		""" Generate traces with all possible combination of flags.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		self.printCustomFlaglist = True
		traces 		= []
		functionList 	= ( 'fw_handshake_2_4_tkip' , 'fw_handshake_4_4_tkip' , 'gk_handshake_2_2_tkip' )
		functionList   += ( 'fw_handshake_2_4_aes'  , 'fw_handshake_4_4_aes'  , 'gk_handshake_2_2_aes' )
		flagSet 	= self.__getAllFlagCombinations()
		
		for flagOptions in flagSet:
			for selectedFunction in functionList:
				newTrace = copy( trace )
				
				# Iterate the messages in the trace and find one that matches the selected
				# function, and update its keywords.
				for x , message in enumerate( newTrace ):
					currentFunction = message[1].func.func_name
					if currentFunction == selectedFunction:
						if message[1].keywords is None:
							newFunction = partial( message[1].func , customFlaglist=flagOptions )
							newTrace[x] = ( message[0] , newFunction )
						else:
							newFunction = partial( message[1].func , customFlaglist=flagOptions )
							newTrace[x] = ( message[0] , newFunction )
							newTrace[x][1].keywords.update( message[1].keywords )
						# Append the resulting trace.
						traces.append( ( newTrace , validationType ) )
						break
					
		# Assert that we have generated the expected number of traces.
		assert( len( traces ) == len( flagSet )*3 ), \
			'Internal error; invalid number of generated traces.'
		return traces
	
	def __generateVendorElements( self , trace , validationType ):
		""" Generate traces with all possible combination of vendor information elements.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		supported  = ( 'NONE' , 'TKIP_TKIP_PSK' , 'TKIP_AES_PSK' , 'TKIP_TKIPAES_PSK' )
		supported += ( 'AES_TKIP_PSK' , 'AES_AES_PSK' , 'AES_TKIPAES_PSK' )
		
		for vendorInfo in supported:
			newTrace = copy( trace )
			
			# Iterate the messages in the trace and find one that matches the selected
			# function, and update its keywords.
			for x , message in enumerate( newTrace ):
				currentFunction = message[1].func.func_name
				if 'associationRequest' == currentFunction:
					if message[1].keywords is None:
						newFunction = partial( message[1].func , vendor=vendorInfo )
						newTrace[x] = ( message[0] , newFunction )
					else:
						newFunction = partial( message[1].func , vendor=vendorInfo )
						newTrace[x] = ( message[0] , newFunction )
						newTrace[x][1].keywords.update( message[1].keywords )
						newTrace[x][1].keywords.update( vendor=vendorInfo ) # Overwrite original vendor info.
					# Append the resulting trace.
					for x in self.__generateVendorElementsHelper( newTrace , validationType , supported ):
						traces.append( x )
		
		# Assert that we have generated the expected number of traces.
		assert( len( traces ) == len( supported )**2 ), \
			'Internal error; invalid number of generated traces.'
		return traces
		
	def __generateVendorElementsHelper( self , trace , validationType , supported ):
		""" Generate traces with all possible combination of vendor information elements.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		functionList = ( 'fw_handshake_2_4_tkip' , 'fw_handshake_2_4_aes' )
		
		for selectedFunction in functionList:
			for vendorInfo in supported:
				newTrace = copy( trace )
				
				# Iterate the messages in the trace and find one that matches the selected
				# function, and update its keywords.
				for x , message in enumerate( newTrace ):
					currentFunction = message[1].func.func_name
					if currentFunction == selectedFunction:
						if message[1].keywords is None:
							newFunction = partial( message[1].func , vendor=vendorInfo )
							newTrace[x] = ( message[0] , newFunction )
						else:
							newFunction = partial( message[1].func , vendor=vendorInfo )
							newTrace[x] = ( message[0] , newFunction )
							newTrace[x][1].keywords.update( message[1].keywords )
							newTrace[x][1].keywords.update( vendor=vendorInfo ) # Overwrite original vendor info.
						# Append the resulting trace.
						traces.append( ( newTrace , validationType ) )
		
		# Assert that we have generated the expected number of traces.
		assert( len( traces ) == len( supported ) ), \
			'Internal error; invalid number of generated traces.'
		return traces
	
	def __generateNonces( self , trace , validationType ):
		""" Generate traces with all possible combination of nonces.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		functionList 	= ( 'fw_handshake_4_4_tkip' , 'gk_handshake_2_2_tkip' )
		functionList   += ( 'fw_handshake_4_4_aes'  , 'gk_handshake_2_2_aes' )
		nonceOptions	= ( 'supplicant' , 'authenticator' , 'random' )
		
		for nonceOption in nonceOptions:
			for selectedFunction in functionList:
				newTrace = copy( trace )
			
				# Iterate the messages in the trace and find one that matches the selected
				# function, and update its keywords.
				for x , message in enumerate( newTrace ):
					currentFunction = message[1].func.func_name
					if selectedFunction == currentFunction:
						if message[1].keywords is None:
							newFunction = partial( message[1].func , addNonce=nonceOption )
							newTrace[x] = ( message[0] , newFunction )
						else:
							newFunction = partial( message[1].func , addNonce=nonceOption )
							newTrace[x] = ( message[0] , newFunction )
							newTrace[x][1].keywords.update( message[1].keywords )
						# Append the resulting trace.
						traces.append( ( newTrace , validationType ) )
		
		# Assert that we have generated the expected number of traces.
		assert( len( traces ) == len( nonceOptions )*2 ), \
			'Internal error; invalid number of generated traces.'
		return traces
	
	def __generateReplayCounter( self , trace , validationType ):
		""" Generate traces with odd replay counters.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		functionList 	= ( 'fw_handshake_2_4_tkip' , 'fw_handshake_4_4_tkip' , 'gk_handshake_2_2_tkip' )
		functionList   += ( 'fw_handshake_2_4_aes' , 'fw_handshake_4_4_aes' , 'gk_handshake_2_2_aes' )
		rcOptions = ( 'lower' , 'higher' )
		
		for rcOption in rcOptions:
			for selectedFunction in functionList:
				newTrace = copy( trace )
			
				# Iterate the messages in the trace and find one that matches the selected
				# function, and update its keywords.
				for x , message in enumerate( newTrace ):
					currentFunction = message[1].func.func_name
					if selectedFunction == currentFunction:
						if message[1].keywords is None:
							newFunction = partial( message[1].func , customRC=rcOption )
							newTrace[x] = ( message[0] , newFunction )
						else:
							newFunction = partial( message[1].func , customRC=rcOption )
							newTrace[x] = ( message[0] , newFunction )
							newTrace[x][1].keywords.update( message[1].keywords )
						# Append the resulting trace.
						traces.append( ( newTrace , validationType ) )
		
		# Assert that we have generated the expected number of traces.
		assert( len( traces ) == len( rcOptions )*3 ), \
			'Internal error; invalid number of generated traces.'
		return traces
		
	def __generateRandomData( self , trace , validationType ):
		""" Generate traces with random data.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		functionList 	= ( 'fw_handshake_4_4_tkip' , 'gk_handshake_2_2_tkip' )
		functionList   += ( 'fw_handshake_4_4_aes' , 'gk_handshake_2_2_aes' )
		dataOptions	= ( 'data' , 'dataNoLength' , 'dataShortLength' , 'dataLongLength' )
		
		for dataOption in dataOptions:
			for selectedFunction in functionList:
				newTrace = copy( trace )
			
				# Iterate the messages in the trace and find one that matches the selected
				# function, and update its keywords.
				for x , message in enumerate( newTrace ):
					currentFunction = message[1].func.func_name
					if selectedFunction == currentFunction:
						if message[1].keywords is None:
							newFunction = partial( message[1].func , addData=dataOption )
							newTrace[x] = ( message[0] , newFunction )
						else:
							newFunction = partial( message[1].func , addData=dataOption )
							newTrace[x] = ( message[0] , newFunction )
							newTrace[x][1].keywords.update( message[1].keywords )
						# Append the resulting trace.
						traces.append( ( newTrace , validationType ) )
		
		# Assert that we have generated the expected number of traces.
		assert( len( traces ) == len( dataOptions )*2 ), \
			'Internal error; invalid number of generated traces.'
		return traces
		
	def __generateTKIPMICFailure( self , trace ):
		""" Generate traces that indicate a TKIP MIC Failure Report, this might eventually
			result in a Denial of Service (DoS). Such a trace does not require to be 
			validated.
		"""
		assert( trace is not None and trace is not [] ), \
			'The given trace does not exist or is empty.'
		traces = []
		functionList 	= ( 'gk_handshake_2_2_aes' )
		customFlaglist	= [ 'HMAC_SHA1_AES' , 'group' , 'mic' , 'error' , 'request' ]
		newTrace 	= copy( trace )
		numCopies	= 50
				
		# Iterate the messages in the trace and find one that matches the selected
		# function, and update its keywords.
		for x , message in enumerate( newTrace ):
			if message[1].func.func_name in functionList:
				if message[1].keywords is None:
					newFunction = partial( message[1].func , customFlaglist=customFlaglist )
					newTrace[x] = ( message[0] , newFunction )
				else:
					newFunction = partial( message[1].func , customFlaglist=customFlaglist )
					newTrace[x] = ( message[0] , newFunction )
					newTrace[x][1].keywords.update( message[1].keywords )
					
				# Append the resulting trace.
				for numCopy in xrange( numCopies ):
					traces.append( ( newTrace , None ) )
		
		# Assert that we have generated the expected number of traces.
		assert( len( traces ) == numCopies ), \
			'Internal error; invalid number of generated traces.'
		return traces
		
	######################################################################################
	### Helpers ##########################################################################
	######################################################################################
	
	def __removeDuplicates( self , traces , traceOriginal ):
		""" Remove duplicate traces from the set.
		"""
		trimmed = []
		for trace in traces:
			unseenTrace = True
			if self.__areTracesEqual( trace[0] , traceOriginal ) == False:
				for trimm in trimmed:
					if self.__areTracesEqual( trace[0] , trimm[0] ) == True:
						unseenTrace = False
				if unseenTrace == True:
					trimmed.append( trace )
		return trimmed
	
	def __areTracesEqual( self , traceA , traceB ):
		""" Compares two traces and return true if they are equal, false otherwise.
		"""
		if len(traceA) != len(traceB):
			return False
		for x in xrange( len( traceA )):
			# If the function name and keywords do not differ, it must be equal.
			if traceA[x][1].func.func_name != traceB[x][1].func.func_name:
				return False
			if traceA[x][1].keywords != traceB[x][1].keywords:
				return False
		return True
	
	def __getTransmitTuples( self , trace , trimProbe = False ):
		""" Return a set of all (TRANSMIT,RECEIVE)-tuples.
		"""
		tuples = []
		for index , message in enumerate( trace ):
			if message[0] == 'TRANSMIT' and index < len( trace )-1:
				if trace[index+1][0] == 'RECEIVE':
					tuples.append( ( message , trace[index+1] ) )
		if trimProbe is True:
			tuplesNew = []
			for tuple in tuples:
				if tuple[0][1].func.func_name != 'probeRequest':
					tuplesNew.append( tuple )
			tuples = tuplesNew
		return tuples
	
	def __getAllFlagCombinations( self ):
		""" Get the set of all combination of flaglists. Currently 8 options, resulting
			in 2**8 or 256 combinations; 3 minute run-time estimate.
		"""
		flaglistSet	= []
		flaglistDefault = [ 'HMAC_SHA1_AES' ] # HMAC_MD5_RC4 / HMAC_SHA1_AES
		options 	= [ 'pairwise' , 'install' , 'ack' , 'mic' , 'secure' , 'error' , 'request' , 'encrypted' ]
		
		# Generate a combination of the default flaglist plus all the possible options.
		for x in xrange( len(options) + 1 ):
			for subset in combinations( options , x ):
				newFlaglist = copy( flaglistDefault )
				for flag in subset:
					newFlaglist.append( flag )
				flaglistSet.append( newFlaglist )
		
		# Assert on the length and return the generated set of flaglists.
		assert( len(flaglistSet) == 2**len(options) ), \
			'Internal Error; Invalid number of flaglist combinations.'
		return flaglistSet
		
	######################################################################################
	### Default Traces ###################################################################
	######################################################################################
	
	def __getTraceOpen( self ):
		""" Get the default trace.
		"""
		validationType 	= 'OPEN'
		trace 		= []
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.beacon ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.probeRequest ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.probeResponse ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.authenticationRequest , algorithm='open' ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.authenticationResponse ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.associationRequest ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.associationResponse ) ) )
		return ( trace , validationType )
	
	def __getTraceWEP( self ):
		""" Get the default trace using WEP.
		"""
		validationType 	= 'WEP'
		trace 		= []
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.beacon ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.probeRequest ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.probeResponse ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.authenticationRequest , algorithm='sharedkey' ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.authenticationResponse ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.authenticationRequest , algorithm='sharedkey' , transmitWepChallenge=True ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.authenticationResponse ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.associationRequest ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.associationResponse ) ) )
		return ( trace , validationType )
		
	def __getTraceTKIP( self ):
		""" Get the default trace using TKIP.
		"""
		validationType 	= 'TKIP'
		trace 		= []
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.beacon ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.probeRequest ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.probeResponse ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.authenticationRequest , algorithm='open' ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.authenticationResponse ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.associationRequest , vendor='TKIP_TKIP_PSK' ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.associationResponse ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleEAPoL.fw_handshake_1_4 ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleEAPoL.fw_handshake_2_4_tkip , vendor='TKIP_TKIP_PSK' ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleEAPoL.fw_handshake_3_4_tkip ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleEAPoL.fw_handshake_4_4_tkip ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleEAPoL.gk_handshake_1_2_tkip ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleEAPoL.gk_handshake_2_2_tkip ) ) )
		return ( trace , validationType )
		
	def __getTraceAES( self ):
		""" Get the default trace using AES.
		"""
		validationType 	= 'AES'
		trace 		= []
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.beacon ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.probeRequest ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.probeResponse ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.authenticationRequest , algorithm='open' ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.authenticationResponse ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleMgmt.associationRequest , vendor='AES_AES_PSK' ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleMgmt.associationResponse ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleEAPoL.fw_handshake_1_4 ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleEAPoL.fw_handshake_2_4_aes , vendor='AES_AES_PSK' ) ) )
		trace.append( ( 'RECEIVE'  , partial( self.handleEAPoL.fw_handshake_3_4_aes ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleEAPoL.fw_handshake_4_4_aes ) ) )	
		trace.append( ( 'RECEIVE'  , partial( self.handleEAPoL.gk_handshake_1_2_aes ) ) )
		trace.append( ( 'TRANSMIT' , partial( self.handleEAPoL.gk_handshake_2_2_aes ) ) )
		return ( trace , validationType )
		
