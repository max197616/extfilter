#include "getdata.h"
#include <stdio.h>
#define statfile "/var/run/extFilter_stat"
void main(char argc, char **argv){
	if(argc!=2){
		fprintf(stderr, "Usage example:\n \tzabbix_data extfilter.discovery\n\t or \n\tzabbix_data allports.received_packets\n",statfile);
		exit(1);
	}
	if((argc==2) && !strcmp(argv[1],"extfilter.discovery")){
		char temp[255];
		memset(temp,0,sizeof(temp));
		FILE *sf=fopen(statfile,"r");
		if(sf==NULL){
			fprintf(stderr, "File %s not found!\n",statfile);
			exit(1);
		}
		puts("{\n\"data\":[");
		int commafirst=1;
		while(fgets(temp,255,sf)!=NULL){
			if(commafirst){
				printf("{\"{#STATPARAM}\":\"%s\"}",getparam(trimall(temp)));
			}else{
				printf(",\n{\"{#STATPARAM}\":\"%s\"}",getparam(trimall(temp)));
			}
			commafirst=0;
		}
		puts("\n]\n}");
		fclose(sf);
	}
	if(argc==2 && 
	(strstr(argv[1],"worker.")!=NULL) || (strstr(argv[1],"allworkers.")!=NULL) || (strstr(argv[1],"allports.")!=NULL) ){
		char temp[255];
		memset(temp,0,sizeof(temp));
		FILE *sf=fopen(statfile,"r");
		if(sf==NULL){
			fprintf(stderr, "File %s not found!\n",statfile);
			exit(1);
		}
		while(fgets(temp,255,sf)!=NULL){
			if( !strcmp(getparam(trimall(temp)),trimall(argv[1])) ){
				puts(getvalue(trimall(temp)));
			}
		}
		fclose(sf);
	}
}
