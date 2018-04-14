#### Automatically store your 433Mhz RF scan codes to your /etc/environment file on the Raspberry Pi

In using the 433Mhz radio to control home outlets using your Raspberry Pi you use executable codesend to send the on/off code to the outlets.
The strategy is to store these codes in /etc/environment and pull them to control the outlets. You detect them by using a remote control with
an installed 433Mhz receiver on the breadboard connected to the Pi via GPIO and executable RFSniffer. Whenever you click on the on/off button
near the receiver RFSniffer picks the code and displays it on the console. You then copy the code and paste it in /etc/environment and choose
an environment variable for it.

This process requires manual interventions and edits to /etc/environment.

RFSniffer has been modified so it captures the scans and automatically updates /etc/environment with a naming scheme that you pick for your 
environment variables.

RFSniffer has been modified from [Tim Leland's](https://github.com/timleland/rfoutlet) with the new functionality. The following is a summary of
how the improved RFSniffer operates:

  1. The default orignal function is maintained
      i.e. when you point the remote at the receiver and click, RFSniffer displays the code and pulse length the receiver reads and
      keeps doing that until you exit (ctrl-c) 
  2. The following new functionality is added 

      a. Generate environment variable names based on a stub text and an optional descriptive names string
         - The default stub name is "RF"
         - It also keeps the remote button numbers for an easy matching of button and function/outlet name
         - If a space-separated descriptive names string is passed in then it uses the substring count+1 to capture to ON, OFF, pulse ON, pulse OFF
         - for all the buttons on the remote including the button that turns on/off all the devices listening to the remote

         - for example if the following arguments are passed:

              -b RADIO -d "TV LIGHT FAN BEDROOM"

         then the following is captured:
               RADIO_ON_1_TV
               RADIO_OFF_1_TV
               RADIO_PULSE_ON_1_TV
               RADIO_PULSE_OFF_1_TV

               RADIO_ON_2_LIGHT
               RADIO_OFF_1_LIGHT
               RADIO_PULSE_ON_1_LIGHT
               RADIO_PULSE_OFF_1_LIGHT

               RADIO_ON_1_FAN
               RADIO_OFF_1_FAN
               RADIO_PULSE_ON_1_FAN
               RADIO_PULSE_OFF_1_FAN

               RADIO_ON_1_BEDROOM
               RADIO_OFF_1_BEDROOM
               RADIO_PULSE_ON_1_BEDROOM
               RADIO_PULSE_OFF_1_BEDROOM
 
               RADIO_ON_1_ALL
               RADIO_OFF_1_ALL
               RADIO_PULSE_ON_1_ALL
               RADIO_PULSE_OFF_1_ALL

        if no descriptive names string is supplied but just the stub text then all the above is captured without the descriptive ending.
        If a descriptive names string is supplied and no stub then the above is capture with a stub of "RF"
 
      b. If an environment variable exists already in the /etc/environment and the scheme of stub/descritive name would create an identical name, then
         the variable will be updated with the value captured on the from the receiver. 

      c. If a generated variable does not exist in /etc/environment, it is simply appended to the file.

      d. if you ctrl-c during a scan/capture run you are given the chance to save data captured so far.  


