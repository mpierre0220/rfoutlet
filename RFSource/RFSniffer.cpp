#include "RFSniffer.h"
 
/*
  RFSniffer

  Usage: ./RFSniffer [-p] [-b stubname] [-d "descriptivename i ... descriptivename n]" 
  [] = optional

  Hacked from http://code.google.com/p/rc-switch/
  by @justy to provide a handy RF code sniffer

  @mpierre0220 modified to automatically add the scans to /etc/environment

  The following features are available
  (1) The default orignal function is maintained
      i.e. when you point the remote at the receiver and click, RFSniffer displays the code and pulse length the receiver reads and
      keeps doing that until you exit (ctrl-c) 
  (2) The following new functionality is added 
      a. Generate environment variable names based on a stub text and an optional descriptive names string
         The default stub name is "RF"
         It also keeps the remote button numbers for an easy matching of button and function/outlet name
         If a space-separated descriptive names string is passed in then it uses the substring count+1 to capture to ON, OFF, pulse ON, pulse OFF
         for all the buttons on the remote including the button that turns on/off all the devices listening to the remote

         for example if the following arguments are passed:

              -b RADIO -d "TV LIGHT FAN BEDROOM"

         then the following is captured:
               RADIO_ON_1_TV
               RADIO_OFF_1_TV
               RADIO_PULSE_ON_1_TV
               RADIO_PULSE_OFF_1_TV

               RADIO_ON_2_LIGHT
               RADIO_OFF_2_LIGHT
               RADIO_PULSE_ON_2_LIGHT
               RADIO_PULSE_OFF_2_LIGHT

               RADIO_ON_3_FAN
               RADIO_OFF_3_FAN
               RADIO_PULSE_ON_3_FAN
               RADIO_PULSE_OFF_3_FAN

               RADIO_ON_4_BEDROOM
               RADIO_OFF_4_BEDROOM
               RADIO_PULSE_ON_4_BEDROOM
               RADIO_PULSE_OFF_4_BEDROOM
 
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
*/

char *trim(char *datastring)
{
 /*
  This functions trims leading and trailing white space characters
  White space characters are the following:
  " "  - space
  \n   - line feed
  \r   - carriage return
  \t   - horizontal tab
  \v   - vertical tab
  \f   - feed character	
  function isspace() returns true if the character passed to it is any of the above

 */
  // Remove space in front of the string
  while(isspace((unsigned char)*datastring)){ 
     datastring++;
  }

  if(!*datastring){  // only the zero character is left? then we're done
     return datastring;
  }

  //we will now start looking for spaces characters from the end of datastring
  // remove spaces at the end of the datastring

  char * fromend = datastring + strlen(datastring) - sizeof(char);
  while(fromend > datastring && isspace((unsigned char)*fromend)){
     fromend--;
  }

  // Mark the end of the string with the zero character
  memset(fromend+1,0,sizeof(char));

  return datastring;
}

int isCommented(char *entry){
   char * nent=entry;
   if (*(trim(nent))=='#') {
      return true;
   } else {
      return false;
   }
}


void usage(char *prog){
   printf("Usage: %s [-b stubname] [-d \"descriptivename i ... descriptivename n]\" \n", prog);
   printf("Where stubname is the stub string used to create scan names\n");
   printf("      For example a basename of RF, will create name of RF_ON_1 and RF_OFF_1 RF_PULSE_ON, RF_ON_ALL and, RF_OFF_ALL if no descriptive name is given\n"); 
   printf("      descriptivename i is an optional space-separated string, quoted list of names associated with button numbers on the remote\n");
 }
void shownames(){
   int i=0;
   while (strcmp(dnames[i]," ")!=0){
       printf("%s\n",dnames[i++]);
   }
}
int showScans(){
   if (scansCount){
      printf("\n");
      printf("Values captured are as follows:\n");
      printf("______________________________\n\n");
      for (int i=0; i<scansCount+1; i++){
         printf("%s:\t%i\n", rscans[i]->nameon,rscans[i]->on );
         printf("%s:\t%i\n",rscans[i]->namepulseon, rscans[i]->pulseon);
         printf("%s:\t%i\n", rscans[i]->nameoff,rscans[i]->off );
         printf("%s:\t%i\n",rscans[i]->namepulseoff, rscans[i]->pulseoff);
      }
   }
   return scansCount;
}

char * replaceString(char *sourcestr, char *candidate, char *replacement) {
   char *start = strstr(sourcestr,candidate);
   char *newstring=(char *)malloc(strlen(sourcestr)-strlen(candidate)+strlen(replacement));
   if (start==NULL) {
      return sourcestr;
   } else {
      *start=0;
      char *rest=++start;
      start--;
      char *remainder=rest+(strlen(candidate))-1;
      if (strlen(remainder)>0){
          sprintf(newstring,"%s%s%s",sourcestr,replacement,remainder);
      } else {
          sprintf(newstring, "%s%s",sourcestr,replacement);
      }
   }
   return newstring;
}

int last=false;
void dumpEntry(struct EnvEntry * entry){
   printf("EnvEntry: name=>%s\nvalue==>%s\nline=>%s\nmodify==>%i\n", entry->name, entry->value, entry->line, entry->modify);
}
void scanEnvForBadChars(char c){
   int i=0;
   char *scan=(char *)malloc(2);
   *scan=c;
   *(scan+1)=0;
   int bad=false;
   while(envEntries[i]){
     if (strstr(envEntries[i]->value,scan)) {
        printf("bad char detected in %s\n",envEntries[i]->value);
        getchar();
        bad=true;
     } else if(strstr(envEntries[i]->line,scan)) {
        printf("bad char detected in %s at index %d\n",envEntries[i]->line,i);
        getchar();
        bad=true;
     }
     i++;
   } 
   if (!bad) {
      printf("no bad chars in the environment\n");
      getchar();
   }
   free(scan);
}

//parse the environment entries and put them is a name-value structure
//mark entries whose variables were captured as modifiable and don't touch the others
//keep the original line as read from /etc/environment
struct EnvEntry * parse_entry(char *eentry, struct RadioScans *rscans[]){
   /*
      eentry = line from /etc/environment
      rscans = array of ptrs to values scanned from the RF remote control
      
      returns an EnvEntry * that contains the parsed environment line
      
      for example if this entry is passed in: "export RF_ON_1_TV=5671234"
      The return structure contains the following
          ==>name=RF_ON_1_TV
          ==>value=5671234
          ==>oldval=5671234
          ==>line="export RF_ON_1_TV=5671234"
          ==>modify= true | false (if rscans contains the same name, then true)
   */
   #ifdef debug
   printf("Inside of parse_entry: entry==>%s\n", eentry);
   #endif
   char *entry=strdup(eentry);
   struct EnvEntry * ent=new EnvEntry();
   ent->name=NULL;
   ent->value=NULL;
   ent->line=(char *)malloc(strlen(entry)+1);
   strcpy(ent->line,entry);
   #ifdef debug 
   printf("Just saved line: %s\n", entry);
   #endif
   ent->modify=false;
   //printf("In parse_entry [%s]\n", entry);
   //char *test=trim(entry);
   //if (strlen(test) < 2){
   //    printf("Leaving parse_entry cause the length of the line is <2\n");
   //    return ent;
   //}
   if (!isCommented(entry)) {
      char *token1=strtok(entry,"=");
      #ifdef debug
      printf("Token1=[%s]\n", token1);
      #endif
      char * token2=strtok(NULL, "=");
      //printf("Token2=[%s]\n",token2);
      char * tokenname=trim(strtok(token1,"export"));
      //printf("Token3 [%s]\n", trim(token3));
      char *tokenval=getenv(tokenname); 
      if (tokenval==NULL){
          printf("\n\n%sUnexpected error getting the value for environment variable %s. Ensure that you source /etc/environment.\n",RED,tokenname);
          printf("%sEnsure also that you are running this program in the regular user's context, not in root's\n",RED);
          exit(1);
      }
      char *tokencomment=strtok(NULL,tokenval);
      //printf("Token4 [%s]\n", trim(token4));
      ent->name=trim(tokenname);
      ent->value=trim(tokenval);
      int i = 0;
      int modify=false;
      int m1,m2,m3,m4;
      while (rscans[i] != NULL) {
         m1=m2=m3=m4=false;
      
         #ifdef debug
         printf("iteration %d\n", i);
         printf("comparing %s  to %s, %s, %s, %s\n", ent->name, rscans[i]->nameon,rscans[i]->nameoff,rscans[i]->namepulseon, rscans[i]->namepulseoff);
         #endif
         m1 = strcmp(ent->name, rscans[i]->nameon);
         #ifdef debug
         printf("comparing %s to %s to yield %i\n", ent->name, rscans[i]->nameoff, (m2 = strcmp(ent->name, rscans[i]->nameoff)));
         #endif
         m2 = strcmp(ent->name, rscans[i]->nameoff);
         m3 = strcmp(ent->name, rscans[i]->namepulseon);
         m4 = strcmp(ent->name, rscans[i]->namepulseoff);
         #ifdef debug
         printf("m1=%i m2=%i m3=%i m4=%i\n", m1,m2,m3,m4);
         #endif
         if (m1=0 || m2==0 || m3==0 || m4==0) {
            #ifdef debug
            printf("m1=%i m2=%i m3=%i m4=%i\n",m1,m2,m3,m4);
            #endif
            modify=true;
            break;
         }
         i++;
      }
       
      ent->modify=modify;
      //dumpEntry(ent);

   }  
   //printf("parse_entry: Returning modify=%i\n",ent->modify);
   
   #ifdef debug
   dumpEntry(ent);
   printf("Leaving parse_entry with entry==>%s\n",eentry);
   #endif
   return ent;   
}
int getNewValue(char *name, RScans rscans[]){
   //return the scanned value for key
   int i=0;
   while (rscans[i]) {
      if (strcmp(name,rscans[i]->nameon)==0) {
         return rscans[i]->on;
      } else if (strcmp(name, rscans[i]->nameoff)==0){
         return rscans[i]->off;
      } else if (strcmp(name, rscans[i]->namepulseon)==0){
         return rscans[i]->pulseon;
      } else if (strcmp(name, rscans[i]->namepulseoff)==0){ 
         return rscans[i]->pulseoff;
      }
      i++;
   }
   return 0;
}
int save_environment(char * buffer){
   //if the user ctrl-c while we're here, we will not reenter
   int rc=system("sudo cp /etc/environment /etc/environment.bak");
   if (rc!=0){
       printf("%sUnexpected error backing /etc/environment, into /etc/environment.bak, operation aborted\n",RED);
       exit(1);
   }    
   char fname[]="/tmp/environXXXXXX";
   int fd=mkstemp(fname);
   if (fd==-1){
       printf("%sUnexpected error creating a temporary file, operation aborted\n",RED);
       exit(1);
   }
   //printf("tmp file name %s \n"  ,fname);
   write(fd,buffer, strlen(buffer));
   close(fd);
   char *cmd=(char *)malloc(256);
   sprintf(cmd,"sudo chmod 644 %s",fname);
   rc=system(cmd);
   if (rc!=0){
       printf("%sUnexpected error changing access to a temporary file, operation aborted\n",RED);
       exit(1);
   }
   sprintf(cmd,"sudo mv %s /etc/environment",fname);
   rc=system(cmd);
   if (rc!=0){
       printf("%sUnexpected error renaming a temporary file into /etc/environment, operation aborted\n",RED);
       exit(1);
   }
   if (access("/etc/environment", F_OK)!=-1) {
       unlink("/etc/environment.bak");
   } else {
       printf("%sUnexpected error accessing /etc/environment, use /etc/environment.bak, operation aborted\n",RED);
       exit(1);
   }    
   printf("Environment file saved\n");
}

void promptToSaveEnvironment(char *buffer){
   printf("\nPress y and enter to save the above buffer to /etc/environment or n and enter to abort and exit\n");
   char c=0; 
   while((c != no) && (c != yes)) {
      c=getchar();
      if (c==yes){
         save_environment(buffer);
         exit(0);
      } else if (c==no) {
         exit(0);
      }
  }
}

char * dumpEnvEntries(int buff){
   //This functions dumps to screen the entries that will be written to /etc/environment
   //or creates a buffer that can be written to /etc/environment
   //if argument buff is 0, then the function displays to screen and does not create buffer 
   int i=0;
   char *buffer=NULL;
   
   if (envEntries[i]){
      printf("\n/etc/enviroment will look as follows:\n____________________________\n");
      #ifdef debug
      scanEnvForBadChars('!');
      #endif
   }
   while (envEntries[i]){
      if (!buff) {
         if (envEntries[i]->modify) {
            printf("==> name=%s value=%s\n", envEntries[i]->name, envEntries[i]->value);
            printf("==> line=%s\n", envEntries[i]->line);
         } else {
            printf("dumpEnvEntries, unmodified: %s\n",envEntries[i]->line);
            envEntries[i]->line=trim(envEntries[i]->line);
            printf("%s\n",envEntries[i]->line);
         }
      } else {
         if (!buffer){
            //allocate 5 Meg for the environment buffer
            buffer=(char *)malloc(5000*1024+1);
            memset(buffer,0, 5000*1024);
            if (envEntries[i]->modify){
               sprintf(buffer,"%s\n",trim(replaceString(envEntries[i]->line,envEntries[i]->oldval,envEntries[i]->value)));
            } else {
               sprintf(buffer,"%s\n",trim(envEntries[i]->line));
            }  
         } else {
            if (envEntries[i]->modify){
               //dumpEntry(envEntries[i]);
               //printf("About to replace %s with %s in %s\n", envEntries[i]->oldval, envEntries[i]->value, envEntries[i]->line);
               //getchar();
               buffer=strcat(buffer,trim(replaceString(envEntries[i]->line,envEntries[i]->oldval,envEntries[i]->value)));
               buffer=strcat(buffer,"\n");
            } else {
               #ifdef debug
               printf("[%s]\n[%s]\n",envEntries[i]->line,envEntries[i]->value);
               #endif
               buffer=strcat(buffer,trim(envEntries[i]->line));
               buffer=strcat(buffer,"\n");
               #ifdef debug
               if (strstr(buffer,"!")) {
                   printf("detected a bad char in the buffer at index %d\n", i);
                   printf("%s\n",trim(envEntries[i]->line));
                   printf("%s\n",trim(envEntries[i]->value));
                   getchar();
               }
               #endif
            }
         } 
      }
      i++;
   }
   if (buffer) {
      printf("%s",buffer);
      return buffer;
   }
   return NULL;
}

void adjustEnvLine(char *name, int value){
   int i=0;
   int found=false;
   //printf("Adjusting environment with %s and %d\n",name, value);
   if (!name) {
      return;
   }
   if (*name==0){
      return;
   }
   while (envEntries[i]){
      if (strcmp(envEntries[i]->name,name)==0){
         envEntries[i]->oldval=(char *)malloc(strlen(envEntries[i]->value)+1);
         strcpy(envEntries[i]->oldval,envEntries[i]->value); 
         //envEntries[i]->value=(char *)malloc(32;
         memset(envEntries[i]->value,0,strlen(envEntries[i]->value));
         sprintf(envEntries[i]->value,"%d",value);
         envEntries[i]->modify=true;
         found=true;
         break;
      }
      i++;
   }
   if (!found) {
      #ifdef debug
      if (i>0){
         printf("dumping entry %d\n",i-1);
         dumpEntry(envEntries[i-1]);
      }
      printf("adding at index %d\n",i);
      #endif
      envEntries[i]=new EnvEntry();
      envEntries[i]->name =(char *)malloc(strlen(name)+1);
      strcpy(envEntries[i]->name, name);
      envEntries[i]->value=(char *)malloc(32);
      //printf("value=%d\n",value); 
      sprintf(envEntries[i]->value,"%d",value);
      #ifdef debug
      printf("value %s\n",envEntries[i]->value);
      #endif
      int size=strlen("export")+strlen(envEntries[i]->name)+strlen(envEntries[i]->value)+4;
      envEntries[i]->line=(char *)malloc(size);
      memset(envEntries[i]->line,0,size);
      sprintf(envEntries[i]->line,"export %s=%s", trim(envEntries[i]->name), trim(envEntries[i]->value));
      #ifdef debug
      printf("{%s}\n",envEntries[i]->line);
      if (i>0){
         printf("dumping entry %d\n",i-1);
         dumpEntry(envEntries[i-1]);
      }
      #endif
   } 
   #ifdef debug
   scanEnvForBadChars('!');
   #endif       
}

struct EnvEntry ** parse_environment(char *envLines[], int len, struct RadioScans *rscans[]){
   envEntries[len]=NULL;
   #ifdef debug
   printf("In parse_environment #1 with %i entries\n",len);
   #endif
   int i=0;
   while (i < len) {
       #ifdef debug
       printf("Going call parse_entry with envLines[%i]=%s\n",i, envLines[i]);
       #endif
       envEntries[i]=parse_entry(envLines[i],rscans);
       #ifdef debug
       printf("In parse_environment #2: iteration %i, just saved line envLines[%i]: %s into %s\n",i, i, envLines[i], envEntries[i]->line); 
       printf("returned data from parse_entry: %s %s from %s\n",envEntries[i]->name, envEntries[i]->value, envEntries[i]->line);
       #endif
       i++;
   }
   return envEntries;       
}
void adjustEnvironmentBuffer(RScans rs[]) {
   int i=0;
   #ifdef debug
   printf("in adjustEnvironmentBuffer \n");
   #endif
   while (rs[i]){
      #ifdef debug
      printf("iteration %d: %s\n",i,rs[i]->nameon);
      #endif
      adjustEnvLine(rs[i]->nameon, rs[i]->on);
      adjustEnvLine(rs[i]->nameoff, rs[i]->off);
      adjustEnvLine(rs[i]->namepulseon, rs[i]->pulseon);
      adjustEnvLine(rs[i]->namepulseoff, rs[i]->pulseoff);
      i++;
   }
   #ifdef debug
   printf("in adjustEnvironmentBuffer(), calling for scanEnvForBadChars('!')\n");
   scanEnvForBadChars('!');
   #endif
}

char *checkForDups(char *vals[], int len){
   //printf("checking for duplicates among %d values\n", len);   
   for (int i = 0; i < len; i++){
       for (int j= 0; j<len; j++) {
          if (j==i){
             continue;
          } else if (strcmp(vals[i],vals[j])==0){
             return vals[i];
          } else {
             //printf("compared %s to %s\n",vals[i], vals[j]);
             continue;
          }
       }
   }
   return NULL;
}

//read /etc/environment file line by line
//and adjust the buffer containing that information based on the radio 
struct EnvEntry ** get_environment(struct RadioScans *rscans[]){
   FILE *fp;
   static char * lines[4096];
   fp=fopen("/etc/environment", "r");
   if (!fp){
      #ifdef debug
      printf("file pointer %i\n",fp);
      #endif
      exit(1);  
   }
   
   char line[4096];
   int index=0;
   while (fgets(line,4096, fp)!=NULL) {
      lines[index]=(char *)malloc(strlen(line)+1);
      strcpy(lines[index],line);
      #ifdef debug
      printf("get_environment #1: environment line %i. %s, %s\n",index+1, line, lines[index]);
      #endif
      index++;
   }
   fclose(fp);
   #ifdef debug
   printf("get_environment, calling parse_environment\n");
   #endif
   //parse the lines and put then in an array * to EnvEntry
   struct EnvEntry **ee = parse_environment(lines, index, rscans);
   #ifdef debug
   for (int i=0; i<index; i++){
       printf("get_environment #2: environment line %i, %s, after parsing: %s\n", i+1, lines[i], ee[i]->line);
   }
   printf("Adjusting the env buffer\n");
   #endif
   //used the values scanned from the remote to update the environnment buffer with new values
   //The original environment record is actually updated with a flag indicating whether its name
   //has been captured during the scans
   //The actual updates will occur in dumpEnvEntries() which is called after one has called this function
   adjustEnvironmentBuffer(rscans);
}

//ctrl-c handler
void intHandler(int dummy) {
   
   if (!inHandler) {
      inHandler=true;  
      keepRunning = 0;
      if (!oldway && !saving) {
         if (showScans()) {
            get_environment(rscans);
            char *buffer=dumpEnvEntries(true);
            promptToSaveEnvironment(buffer);
         }
      }
   }
}

       

int main(int argc, char *argv[]) {
  
     // This pin is not the first pin on the RPi GPIO header!
     // Consult https://projects.drogon.net/raspberry-pi/wiringpi/pins/
     // for more information.

    int reti;
    int value,pulse;
    rscans[maxCount+1]=NULL;
    char msgbuf[100];
    
    //get_environment();
    
     int PIN = 2;
     
     if(wiringPiSetup() == -1) {
       printf("%swiringPiSetup failed, exiting...\n",RED);
       return 0;
     } 
     base=NULL;
    
 
     //setup a ctrl-c handler to print the scans captured	     
     signal(SIGINT, intHandler);
     int i=0;
     //initialize the array of structures needed to keep the scans
     for (i=0; i<maxCount+1; i++){
        rscans[i]			= 	new RadioScans();
        rscans[i]->nameon		=	(char *)malloc(256);
        rscans[i]->nameoff		=	(char *)malloc(256);
        rscans[i]->namepulseon		=	(char *)malloc(256);
        rscans[i]->namepulseoff		=	(char *)malloc(256);
        rscans[i]->on			=	rscans[i]->off=rscans[i]->pulseon=rscans[i]->pulseoff=0;
        memset(rscans[i]->nameon, 0, 256);
        memset(rscans[i]->nameoff,0,256);
        memset(rscans[i]->namepulseon,0,256);
        memset(rscans[i]->namepulseoff,0,256);
        dnames[i]=(char *)malloc(2);
        strcpy(dnames[i]," ");
     }
     rscans[maxCount+1]=NULL;

     int pulseLength = 0;
     for (int i=1; i<argc; i++){
         if (strcmp(argv[i],"-b")==0) {
            if (i+1<argc){
              //free(base);
              base=argv[++i];
              oldway=false;
            } else {
              printf("%s-b switch needs a string for the base radio scan names\n",RED);
              usage(argv[0]);
              exit(1);
            }
         } else if (strcmp(argv[i],"-p")==0) {
            //It does not appear that passing a pulse length changes anything
            //So not passing it in does not break anything, we keeps this flag for historical reasons
            if (i+1<argc) {
               pulseLength = atoi(argv[++i]);
            } else {
               printf("-p switch needs a pulse length value\n");
               usage(argv[0]);
               exit(1);
            }   
         } else if (strcmp(argv[i], "-d")==0){
            if (i+1<argc) {
               char *dname = argv[++i];
               char *token;
               int j=0;
               token=strtok(dname," ");
               dnames[j]=(char *)malloc(64);
               sprintf(dnames[j++],"%s%s",(char *)"_",token);
               while (token=strtok(NULL, " ")) {
                  #ifdef debug
                  printf("going for %i and %s\n",j, token);
                  #endif
                  dnames[j]=(char *)malloc(64);
                  sprintf(dnames[j++],"%s%s",(char *)"_",token);
               }
               char *dup=checkForDups(dnames, j);
               if (dup){
                   printf("%s%s is a duplicate value in the descriptive names list\n",RED,++dup);
                   exit(1);
               }
               doDnames=true;
               oldway=false;
               #ifdef debug
               shownames();
               #endif
            } else {
               printf("%s-d switch needs space separated list of names\n",RED);
               usage(argv[0]);
               exit(1);
            }   
         } else if (strcmp(argv[i], "-h")==0){
            usage(argv[0]);
            exit(0);
         }
     }
     //if (argv[1] != NULL) pulseLength = atoi(argv[1]);
     if (base==NULL){
         base=(char *)malloc(4);
         strcpy(base,"RF");
     }
     
     mySwitch = RCSwitch();
     if (pulseLength != 0) mySwitch.setPulseLength(pulseLength);
     mySwitch.enableReceive(PIN);  // Receiver on interrupt 0 => that is pin #2
     
     
     int on		=	1;
     int prompt_ON	=	true;
     int get_on 	= 	true;
     int get_off 	= 	false;
     int prompt_OFF	=	false;
     for (int i=0; i<MaxEnvLines;i++) {
         envEntries[i]=NULL;
     }
     envEntries[MaxEnvLines]=NULL;

     //loop prompting to click for the appropriate remote control keys to capture the radio codes 
     if (oldway){
        system(cls);
        printf("Click on the remote near the receiver and note the code for the desired keys\n");
     } 
     while(keepRunning) {

        //if we're collecting the scans to automatically update /etc/environment
        if (!oldway) {
          if (prompt_ON){
             if (last){
                printf("Click on the remote near the receiver to capture the ON value for %s_ON_ALL\n",base);
             
             } else {
               printf("Click on the remote near the receiver to capture the ON value for %s_ON_%i%s\n",base,scansCount+1,dnames[scansCount]);
             }
             prompt_ON=false;
          } else if (prompt_OFF) {
             if (last){
                printf("Click on the remote near the receiver to capture the OFF value for %s_OFF_ALL\n",base);
             } else {
                printf("Click on the remote near the receiver to capture the OFF value for %s_OFF_%i%s\n",base,scansCount+1,dnames[scansCount]);
             }
             prompt_OFF=false;
          }
        }
        if (mySwitch.available()) {
           
           value = mySwitch.getReceivedValue();
           pulse = mySwitch.getReceivedDelay();

           //if we're in compatibility mode 
           if (oldway){
              if (value == 0) {
                 printf("%sUnknown encoding\n",RED);
              } else {
                 printf("%-20s%i\n","Received",value );
                 printf("%-20s%i\n","Received pulse",pulse);
              }
              mySwitch.resetAvailable();
           } else {
              if (value==0){
                 printf("%sUnknown encoding\n",RED);
              }  else {    
                 int found=false;
                 for (int i=0; i<maxCount+1; i++){
                    //if we received a code already, don't process it again
                    if (rscans[i]->on==value || rscans[i]->on==pulse){
                       found=true;
                       break;
                    } else if (rscans[i]->off==value || rscans[i]->off==pulse){
                       found=true;
                       break;
                    }
                } 
                if (!found){
                   char index[32];
                   if (!last) {
                      sprintf(index,"%i",scansCount+1);
                   } else {
                      strcpy(index,"ALL");
                      //printf("Going for the last radio readings\n");
                   } 
                   if (!prompt_ON && get_on){
                      prompt_OFF=true;
                      get_on=false;
                      get_off=true;
                      rscans[scansCount]->on=value;
                      rscans[scansCount]->pulseon=pulse;
                      sprintf(rscans[scansCount]->nameon,"%s_ON_%s%s",base,index,dnames[scansCount]);
                      sprintf(rscans[scansCount]->namepulseon, "%s_ON_PULSE_%s%s", base,index, dnames[scansCount]);
                      
                      printf("%-60s%i\n", rscans[scansCount]->nameon, rscans[scansCount]->on );
                      printf("%-60s%i\n", rscans[scansCount]->namepulseon, rscans[scansCount]->pulseon );
                     
                   } else if (!prompt_OFF && get_off) {
                      prompt_ON=true;
                      prompt_OFF=false;
                      get_on=true;
                      get_off=false;
                      rscans[scansCount]->off=value;
                      rscans[scansCount]->pulseoff=pulse;
                      sprintf(rscans[scansCount]->nameoff,"%s_OFF_%s%s",base,index, dnames[scansCount]);
		      sprintf(rscans[scansCount]->namepulseoff, "%s_OFF_PULSE_%s%s", base, index, dnames[scansCount]);
                     
                      printf("%-60s%i\n",rscans[scansCount]->nameoff, rscans[scansCount]->off );
                      printf("%-60s%i\n",rscans[scansCount]->namepulseoff, rscans[scansCount]->pulseoff);
                     
                      if (last) {
                         saving=true;
                         //our job is complete so get the environment file and merge it with
                         showScans();
                           
                         //struct EnvEntry **eEnt=;
                         get_environment(rscans);
                         #ifdef debug
                         scanEnvForBadChars('!');
                         #endif
                         char *buffer=dumpEnvEntries(true);
                         promptToSaveEnvironment(buffer);
                         //exit(0);                
                      }
                      
                      scansCount++;
                      #ifdef debug
                      printf("dnames[%d]=%s\n",scansCount,dnames[scansCount]);
                      printf("incremented scansCount to %d\n", scansCount);
                      #endif
                      if (doDnames){
                         //if using descriptive names then their count determines when we stop
                         //otherwise we use maxCount

                         //The last value in the dnames array is " ", so when we hit it, we wrap up
                         if (strcmp(dnames[scansCount], " ")==0){
                            last=true;
                            #ifdef debug                            
                            printf("set last to true\n");
                            #endif
                         } else {
                            #ifdef debug
                            printf("Not at the end, scansCount=%d\n",scansCount);
                            #endif
                         }
                      } else {
                         if (scansCount==maxCount){
                            last=true;
                         }
                      }
                   }
                }
             }
    
             mySwitch.resetAvailable();
          }  
      }
   }
   exit(0);
}