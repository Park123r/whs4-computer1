#include<stdio.h>

int main(){
    char buffer[100];

    FILE* fp = fopen("test.txt", "w");
    if (fp == NULL) {
        perror("Error opening file");
        return -1;
    }
    fprintf(fp, "Hello, World!\n");
    fprintf(fp, "This is a test file.\n");

    fflush(fp);
    
    fclose(fp);
    printf("작성 완료");
    return 0;



}