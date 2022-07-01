#include <stdio.h>
#include <windows.h>
#include <fltUser.h>

int main() {
	FILE * fptr;
	fopen_s(&fptr, "file.siplatov", "r+");

	if (fptr == 0) {
		return -1;
	}	

	char buf[1024] = { 0 };
	fread_s(buf, 1024, sizeof(char), 1024, fptr);
	printf_s("FILE CONTENTS:%s\n\n", buf);

	char buf_to_write[1024] = { "Some Test Data 2" };
	fseek(fptr, 0, 0); // изменить позицию в начало файла

	fwrite(buf_to_write, sizeof(char), 1024, fptr);
	fflush(fptr); // записывает на диск поток stream //Обнуление (сброс) потоков.
	fclose(fptr);

	return 0;
}