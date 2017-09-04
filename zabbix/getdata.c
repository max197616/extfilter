#include <string.h>
#include <ctype.h>
char* trimall(char* s){
	char *temp=malloc(255);
	memset(temp,0,sizeof(temp));
	int i=0,j=0;
	char c;
	while( (c=*(s+i))!= 0){
		if(!isspace(c)){
			*(temp+j)=c;
			j++;
		}
		i++;
	}
	return temp;
}
char* getparam(char *s){
	char *temp=malloc(255),*c;
	memset(temp,0,sizeof(temp));
	if((c=strchr(s,'='))!=NULL){
		strncpy(temp,s,c-s);
	}
	return temp;
}
char* getvalue(char *s){
	char *temp=malloc(255),*c;
	memset(temp,0,sizeof(temp));
	if((c=strchr(s,'='))!=NULL){
		strcpy(temp,(c+1));
	}
	return temp;
}
