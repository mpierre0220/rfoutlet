#include "RCSwitch.h"
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include <ctype.h>
#include <termios.h>
#include <fcntl.h>

 
 

#define true 		1
#define false 		0 
#define esc 		27
#define yes 		'y'
#define no 		'n'

#define MAGENTA  	"\x1B[35m"
#define WHITE 		"\x1B[37m"
#define RED  		"\x1B[31m"
#define BLUE  		"\x1B[34m"
#define CYAN  		"\x1B[36m"
#define NORMAL 	 	"\x1B[0m"
#define GREEN  		"\x1B[32m"
#define YELLLOW  	"\x1B[33m"

     
RCSwitch mySwitch;

//structure to keep the environment strings
struct EnvEntry {
   char *name;
   char *value;
   char *comment;  //currently not used
   char *line;     //original environment file line
   int  modify;    //if set to true, it means this line will be modified by a scan received from the radio receiver
   char *oldval;   //old value before the new value was captured
} env;

//structure to keep the scans read from the radio receiver
typedef struct RadioScans { 
   char * nameon;              //name for the on button
   int on;		       //value for the on button scan
   char * namepulseon;         //name for the pulse on scan
   int pulseon;                //value of the pulse on scan
   char * nameoff;             //name of the off button 
   int off;                    //value of the off button scan
   char * namepulseoff;        //name for the pulse off scan
   int pulseoff;               //value of pulse off scan
} rscan, * RScans;


const int MaxEnvLines 			= 	8192;
struct EnvEntry * envEntries[MaxEnvLines+1];
const int maxCount			=	4;
RScans rscans[maxCount*2+2];
int scansCount				=	0;
static volatile int keepRunning 	=	1;
char *base;
char cls[]				=	"clear";
char *dnames[maxCount+1];
int doDnames				=	false;	
int oldway				=	true;
int inHandler				= 	false;
int saving				=	false;