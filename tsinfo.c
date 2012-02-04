#include <stdio.h>
#include <stdlib.h>

#define PID_SDT 0x00000011
#define PID_EIT 0x00000012

int getSectionLength(unsigned char*);
int getPid(unsigned char*);
void print_packet(unsigned char*);

int main(int argc, char* argv[])
{
	int byte_count, adaptation_field_byte, payload_start_index, section_length, service_id, descriptor_length;
	int i,j,k;
	int pid;
	unsigned char *buf, tmp;
	FILE *fp;

	if(argc != 2){
		printf("Usage: ./tsinfo filename\n");
		exit(0);
	}

	if((fp = fopen(argv[1], "r")) == NULL){
		printf("open error!!\n");
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
			if(adaptation_field_byte < 0) return -1;
			payload_start_index = 5 + adaptation_field_byte;
			switch(buf[payload_start_index])
			{
				case 0x42 :
					section_length = getSectionLength(buf+payload_start_index);
					printf("section_length = %d\n", section_length);

					service_id = getServiceId(buf+payload_start_index+11);
					printf("service_id = %d\n", service_id);

					descriptor_length = getDescriptorLength(buf+payload_start_index+11);
					printf("descriptor length = %d\n", descriptor_length);
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

	printf("j = %d\n", j);

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
