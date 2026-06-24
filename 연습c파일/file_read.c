#include <stdio.h>

int main() {
    char buffer[100]; // 파일에서 읽어온 글자를 임시로 담을 그릇

    // 1. 파일 열기 (r: read 모드, 파일이 없으면 에러)
    FILE* fp = fopen("test.txt", "r");
    
    if (fp == NULL) {
        printf("파일이 존재하지 않습니다!\n");
        return 1;
    }

    // 2. 파일 끝까지 한 줄씩 읽기 (fgets는 한 줄씩 읽어옴)
    // fp에서 글을 읽어서 buffer에 넣다가, 더 이상 읽을 게 없으면(NULL) 반복문 종료
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer); // 읽어온 내용 화면에 출력
    }

    // 3. 파일 닫기
    fclose(fp);

    return 0;
}