#!/bin/bash 

COUNTER=0

while [  $COUNTER -lt 5 ]; do
	echo Running the ICEPOLE attack for the $COUNTER time
	#./icepole_cryptanalysis -l 500
	echo running the program
	let COUNTER=COUNTER+1 
done