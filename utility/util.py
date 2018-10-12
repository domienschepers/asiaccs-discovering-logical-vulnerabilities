#!/usr/bin/env python2.7
import os

def setBit( value , index ):
	""" Set the index'th bit of value to 1.
	"""
	mask = 1 << index
	value &= ~mask
	value |= mask
	return value

def getBit( value , index ):
	""" Get the index'th bit of value.
	"""
	return (value >> index) & 1
	
def getKeyID( id ):
	""" Get the 8-bit key identifier from an integer.
	"""
	assert( 0 <= id <= 3 ), \
		'The Key ID must be a value between 0 and 3 included.' 
	keyid = 0x00
	if id == 1:
		keyid = setBit( keyid , 6 )
	if id == 2:
		keyid = setBit( keyid , 7 )
	if id == 3:
		keyid = setBit( keyid , 6 )
		keyid = setBit( keyid , 7 )
	return keyid
	
def printTerminalLine( character ):
	""" Print a horizontal line over the full width of the terminal screen.
	"""
	os.system( "printf '%*s\n' \"${COLUMNS:-$(tput cols)}\" '' | tr ' ' " + character )
	