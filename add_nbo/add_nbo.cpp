#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

uint32_t _ntohl(char *file){ // modify -> add function for efficiency
    FILE *fp;
    uint32_t buffer;

    fp = fopen(file, "rb");
    uint32_t a = fread(&buffer, 1, sizeof(buffer), fp);

    fclose(fp);

    if(a==0){
        return htonl(a);
    }
    else {
        printf("\nError: not correct type to change the form\n\n");
        return 0;
    }
}

int main(int argc, char* argv[]){

    if(argc != 3){
        printf("No files\nUsage: add-nbo <file1> <file2>\n\n\n");
    };

    uint32_t s1 = _ntohl(argv[1]);
    uint32_t s2 = _ntohl(argv[2]);

    if(s1==0&&s2==0) return 0;
    else printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", s1, s1, s2, s2, s1+s2);

    return 0;
}

