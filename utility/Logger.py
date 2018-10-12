#!/usr/bin/env python2.7
import datetime

class Logger:
	""" Logs information messages to the console and logfile.
	"""

	# Common color and general markup definitions.
	_WHITE		= '\033[97m'
	_CYAN		= '\033[96m'
	_MAGENTA	= '\033[95m'
	_BLUE		= '\033[94m'
	_YELLOW 	= '\033[93m'
	_GREEN		= '\033[92m'
	_RED 		= '\033[91m'
	_GREY		= '\033[90m'
	_UNDERLINE 	= '\033[4m'
	_BOLD 		= '\033[1m'
	_END 		= '\033[0m'
	
	# Shorthand notations for default markup definitions.
	_ERROR 		= _RED + _BOLD
	
	# Supported default markup definitions.
	ERROR		= ( _ERROR	, 'ERROR' )
	RECEIVED	= ( _YELLOW 	, 'RECEIVED PACKET' )
	TRANSMIT	= ( _GREEN 	, 'TRANSMIT PACKET' )
	KEY		= ( _BLUE 	, 'KEY' )
	EXCEPTION	= ( _ERROR	, 'EXCEPTION' )
	ACTION		= ( _MAGENTA	, 'ACTION' ) 
    
	def __init__( self , filename = 'log.txt' , terminal = True , mode = 'w' ):
		""" Initializer.
		"""
		self.filename 	= filename
		self.terminal 	= terminal
		self.file	= open( self.filename , mode )
		self.file.close()
    	
	def log( self , event , message , error = False ):
		""" Log the given event to the logfile, optionally to the terminal.
		"""
		if self.terminal is True:
			self.__logTerminal( event , message , error )
		self.__logFile( event , message )
		
	def logKey( self , name , value ):
		""" Shorthand method for logging keys.
		"""
		self.log( self.KEY , name + ' (Length ' + str(len(value)) + '): ' + value.encode('hex') )
		
	def __logTerminal( self , event , message , error ):
		""" Log the event to the terminal; error messages have appropriate styling.
		"""
		eventMarkup	= event[0]
		eventMessage	= event[1]
		if error is True:
			message = self._ERROR + message + self._END
		print (eventMarkup + '[%s]' + self._END + ' ' + '%s') % ( eventMessage , message )
	
	def __logFile( self , event , message ):
		""" Log the event to the logfile.
		"""
		typeMessage	= event[1]
		self.file 	= open( self.filename , 'a' )
		self.file.write( str(datetime.datetime.now()) + ' ' )
		self.file.write( '[' + typeMessage + '] ' + message + '\n' )
		self.file.close()
		
