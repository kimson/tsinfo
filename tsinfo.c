#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <errno.h>

#include "tsinfo.h"

#define PID_SDT 0x00000011
#define PID_EIT 0x00000012

int getSectionLength(unsigned char*);
int getPid(unsigned char*);
void print_packet(unsigned char*);
void printUtf8FromUnicode(WCHAR*,int);
void wchar2char(WCHAR*,int,char*);
BOOL parseOption(int,char**,OptionParams*);
void initOptionParams(OptionParams*);

int main(int argc, char* argv[])
{
	int byte_count, adaptation_field_byte, payload_start_index, section_length, service_id, descriptor_length;
	int loop_start_index, service_p_length, service_n_length, chname_length;
	int i,j,k;
	int pid;
	unsigned char *buf, tmp;
	WCHAR chname[256];
	FILE *fp, *outfp;

	OptionParams *options = (OptionParams*)malloc(sizeof(OptionParams));
	initOptionParams(options);
	if(parseOption(argc, argv, options) != TRUE){
		printf("Usage: ./tsinfo -e <encoding> <input filename>\n");
		printf("encoding : UTF-8(default), UTF-16LE\n");
		exit(0);
	}

	if((fp = fopen(options->inputFileName, "r")) == NULL){
		perror("Input file : ");
		return 1;
	}

	buf = (char*)malloc(sizeof(char)*188);

	byte_count = 0;
	j = 0;
	while(fread(buf, sizeof(char), 188, fp) != 0){
		//printf("%d: ", byte_count);
		k = 0;
		pid = getPid(buf);
		//PID == 0x11
		if(pid == PID_SDT){
			//adaptation field ctl = '11'. both.
			if((buf[3] | 0xcf) == 0xff){
				adaptation_field_byte = (int)buf[5];
			//adaptation field ctl = '01'. only payload.
			}else if((buf[3] | 0xcf) == 0xdf){
				adaptation_field_byte = 0;
			//adaptation field ctl = '10' only adaptation field.
			}else if((buf[3] | 0xcf) == 0xef){
				adaptation_field_byte = -1;
			//adaptation field ctl = '00'. error.
			}else{
				adaptation_field_byte = -2;
			}

			printf("adaptation field byte = %d\n", adaptation_field_byte);
			if(adaptation_field_byte < 0) continue;
			payload_start_index = 5 + adaptation_field_byte;
			switch(buf[payload_start_index])
			{
				case 0x42 :
					section_length = getSectionLength(buf+payload_start_index);
					printf("section_length = %d\n", section_length);

					loop_start_index = payload_start_index + 11;
					i = 0;
					while(i < section_length - 12){
						service_id = getServiceId(buf+loop_start_index+i);
						printf("service_id = %d\n", service_id);

						descriptor_length = getDescriptorLength(buf+loop_start_index+i);
						switch(buf[loop_start_index+i+5])
						{
							case 0x48 :
								service_p_length = (int)buf[loop_start_index+i+8];
								service_n_length = (int)buf[loop_start_index+i+9+service_p_length];
								printf("descriptor_length = %d\n", buf[loop_start_index+i+6]);
								printf("service provider name length = %d\n", service_p_length);
								printf("service name length = %d\n", buf[loop_start_index+i+9+service_p_length]);
								chname_length = conv_to_unicode(chname, 512, buf+(loop_start_index+i+10+service_p_length), service_n_length, FALSE);
								printf("chname_length = %d\n", chname_length);
								printUtf8FromUnicode(chname, chname_length);
								/*outfp = fopen("aaa.txt", "a");
								fwrite(chname, 2, chname_length, outfp);
								fputc(0x0d, outfp);
								fputc(0x00, outfp);
								fputc(0x0a, outfp);
								fputc(0x00, outfp);
								fclose(outfp);*/ 
								break;
							default :
								break;
						}

						i += (5 + descriptor_length);
					}
					print_packet(buf);
					
					break;
				default:
					break;
			}
			
		/*}else if(pid == PID_EIT){
			if(is_adaptation_field(buf)){
				printf("is_adaptation_filed!\n");
			}else{
				printf("no adaptation_filed!!\n");
			}
			print_packet(buf);*/
		}
		if(k==1){
			printf("\n\n");
		}
		byte_count += 188;
	}

	free(buf);
	fclose(fp);

	return 0;
}

void print_packet(unsigned char* buf)
{
	int i;
	
	for(i=0;i<188;i++){
		printf("%X  ", buf[i]);
		if((i+1) % 10 == 0){
			printf("\n");
		}
	}
	printf("\n-----------------------\n\n");
}

int getPid(unsigned char* buf)
{
	int pid = 0x00000000;

	pid = pid | (buf[1] & 0x1f);
	pid = pid << 8;
	pid = pid | buf[2];
	
	return pid;

}

int is_adaptation_field(char* buf)
{
	//adaptation field ctl ='11'=both, or adaptation field ctl ='10'=only adaptation field.
	if((buf[3] | 0xcf) == 0xff || (buf[3] | 0xcf) == 0xef){
		return 1;
	//adaptation field ctl = '01'. only payload.
	}else if((buf[3] | 0xcf) == 0xdf){
		return 0;
	}

	//adaptation field ctl = '00'. undefined.
	exit(-1);

}

int getSectionLength(unsigned char* buf)
{
	int section_length = 0x00;
	
	section_length |= buf[1] & 0x0f;
	section_length = section_length << 8;
	section_length |= buf[2];

	return section_length;
}

//payload内のloopの先頭アドレス
int getServiceId(unsigned char* buf)
{
	int service_id = 0x00;

	service_id |= buf[0];
	service_id = service_id << 8;
	service_id |= buf[1];

	return service_id;
}

//payload内のloopの先頭アドレス
int getDescriptorLength(unsigned char* buf)
{
	int descriptor_length = 0x00;

	descriptor_length |= buf[3] & 0x0f;
	descriptor_length = descriptor_length << 8;
	descriptor_length |= buf[4];

	return descriptor_length;
}

void printUtf8FromUnicode(WCHAR* buf, int length)
{
	iconv_t cd;
	char *sbuf, *dbuf, *tmp, *tmp2;
	int ret, slength, dlength;

	dbuf = (char*)malloc(sizeof(char)*length*4);
	sbuf = (char*)malloc(sizeof(char)*length*2);
	wchar2char(buf, length, sbuf);

	tmp = dbuf;
	tmp2 = sbuf;
	slength = length*2;
	dlength = length*4;

	cd = iconv_open("UTF-8", "UTF-16LE");
	if(cd == (iconv_t)-1){
		perror("iconv_open error : ");
		return;
	}

	ret = iconv(cd, &sbuf, &slength, &dbuf, &dlength); 
	if(ret == -1){
		perror("iconv error : ");
		return;
	}
	*dbuf = '\0';
	printf("chname = %s\n", tmp);

	free(tmp);
	free(tmp2);

}

void wchar2char(WCHAR *sbuf, int length, char *dbuf)
{
	int i;

	for(i=0;i<length*2;i+=2){
		dbuf[i+1] = (char)(sbuf[i/2]>>8);
		dbuf[i] = (char)(sbuf[i/2] & 0x00ff);
	}

}

BOOL parseOption(int argc, char* argv[], OptionParams *options)
{
	int i, j;

	for(i=1;i<argc-1;i++){
		if(argv[i][0] == '-'){
			for(j=0;j<strlen(argv[i]);j++){
				switch(argv[i][j])
				{
					case 'e' :
						if(argv[i][j+1] != '\0'){
							printf("-e ENCODE_NAME\n");
							return FALSE;
						}
						i++;
						if(strcmp(argv[i],"UTF-8")==0){
							options->outputEncoding = ENCODE_UTF8;
						}else if(strcmp(argv[i], "UTF-16LE")==0){
							options->outputEncoding = ENCODE_UTF16LE;
						}else{
							printf("指定した文字コードに対応していません\n");
							return FALSE;
						}
						break;
					default :
						return FALSE;
						break;
				}
			}
		}
	}
	options->inputFileName = (char*)malloc(sizeof(char)*strlen(argv[argc-1])+1);
	if(options->inputFileName == NULL){
		printf("Out of memory!!\n");
		return FALSE;
	}
	strcpy(options->inputFileName, argv[argc-1]);

	return TRUE;
}

void initOptionParams(OptionParams* options)
{
	options->outputType = 0;
	options->outputEncoding = ENCODE_UTF8;
	options->inputFileName = NULL;
}
