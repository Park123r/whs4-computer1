#include<stdio.h>

int main(){ 
    char flag_buffer[100] = {0};
    char pass[100] = {0};
    
    FILE* fp = fopen("flag.txt","r");
    if(fp == NULL){
        printf("파일 없음");
        return -1;
    }

    fread(flag_buffer,sizeof(char),20,fp);
    scanf("%s", &pass);


    /*if(strncmp(pass, flag_buffer, 20) == 0){
        printf("정답");
    }
    else{
        printf("오답");
    }
    */

    for(int i = 0; i < 20; i++){      
        if(pass[i] == flag_buffer[i]){
            printf("정답");
        }
        else{
            printf("오답");
        }
    }

   fclose(fp);
   return 0;

}