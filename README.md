sb_bt
=====
Tool to read power production data for SMA Sunnyboy power invertors on a Linux machine.  
Copyright 2012, Creagraphy / Ernst de Moor.


SunnyBoy Bluetooth communications. Reads actual values in a reliable way, and adds them to a CSV file.

This software is to be called from a Cron job, e.g. every 5 minutes.  
It will add the current values to a .csv file, with the date as part of the filename.

Examples of filesnames that are created:  
 - test2012-09-05.csv (with option -f test )
 - /tmp/pv-2-2012-09-05.csv (with option -f /tmp/pv-2- )


Optionally this program will set the internal clock of the SunnyBoy, either once a day or every 5 minutes.  
This is not necessary for this tool, but might be useful to read the graphs lateron with SunnyExplorer.

Tested with a SMA SunnyBoy 2100TL, but expected to work with all SunnyBoy inverters with a piggyback Bluetooth module.


Usage:
------

See for installation instructions: https://github.com/creagraphy/sb_bt/wiki/Installation

I use this software by calling it from Cron, every 5 minutes.  
I use a separate script to upload The resulting CSV file to my webserver, that will add the data to a Mysql DB.  
This is done by the upload.sh script (see below), which is too specific to add it to this repo.

To see the resulting graphs: http://www.web-op-maat.nl/grafieken (Dutch page)

Add in /etc/crontab:

\# Read Sunnyboy values every 5 minute  
\*/5 * * * *   root  /etc/cron.watches/sb_bt -t 1 -a 00:80:25:A4:B6:C2 -p xxxx ; /etc/cron.watches/upload.sh





Commandline options:
--------------------
Usage: sb_bt [OPTION]...  
Read information from SunnyBoy inverter via BlueTooth  
Optionally set the internal clock (not necessary for us, but for SMA Sunny Explorer)

Mandatory arguments:
  - -a ADDRESS        : Bluetooth address of the inverter
  - -p PASSWORD       : User level password of the inverter (default: 0000)

Optional arguments
  - -f FILENAME       : Output filename lead-in (date and csv extension is added, default: /tmp/pv-2- )
  - -t SETTIME        : Set the time of the converter, 1: Once a day, 2: every request
  - -v                : verbose. If off, the application is silent for cron
  - -d LEVEL          : activate debug, 1: status info, 2: additional hexdumps, 3: additional translations
  - -h                : this help info





Files in this repository:
-------------------------
  - README.md : This readme file
  - sb_bt     : A pre-compiled unix executable
  - sb_bt.c   : The source code
  - gpl.txt   : The GNU license

How to compile:  
gcc -lbluetooth -lm -o sb_bt sb_bt.c





Versions:
---------
  - 0.9   : Initial version
  - 0.9.1 : Updated readme, added GNU license text
  - 0.9.2 : readme info fed back to sourcecode
  - 0.9.3 : Remove unnecessary "secret inverter code"
  - 0.9.4 : Some improvements in the Readme file





Limitations: 
------------
  - A Little-Endian processor is assumed, because data structure are built directly in memory (using structs).
    Don't worry, most Linux machines are Little Endian, at least the Intel and ARM processors.
  - Probably only works with SunnyBoy inverters with a piggyback BlueTooth module, not with the newer ones with built-in BT.





Technical notes:
----------------
  - I have put a lot of effort in understanding the communications protocol, and detect CRC errors in messages from the Sunnyboy.
    Therefore the BT communications is very reliable, chances of reading wrong values are very small.
  - I have chosen to communicate with small messages, rather than reading lots of data at once.
    This makes the communications more reliable too.
  - The structure of this code is reasonable, but could be optimised. 
    For instance I could have made a single function to send data and wait for the answer.
    This is now implemented at multiple places.
  - This software uses global data, as it has a very specific use.
      - The config structure contains settings from the commandline.
      - The comms structure holds communications settings like addresses, and the send/receive buffers.
      - The results structure contains the results of querying the Sunnyboys, values for Watt etc.

    making these structures global, keeps the software fast and easy to understand.
    Note however that the functions are _NOT_ re-entrent because of this.
    So if you want to use these functions in a multithreading program, or if you want to write a program 
    that communicates with more than one SunnyBoy, you will have to modify the code!





Special thanks:
---------------
Thanks to the following sources for showing the structuring of data:
  - Yasdi tool of SMA themselves (Serial version of the protocol)
  - Dean Fogarty : https://github.com/angrytongan/dfinvrelay/
  - Wim Hofman and Stephen Collier : http://code.google.com/p/sma-bluetooth/





GNU license
-----------
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
