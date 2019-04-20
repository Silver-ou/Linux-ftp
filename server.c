#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
 
#pragma comment(lib,"libeay32.lib")
#pragma comment(lib,"ssleay32.lib")

#define N 256

#define OPENSSLKEY "privatekey.key"    
#define PUBLICKEY "publickey.key"
#define BUFFSIZE 1024
#define MAXLINE 2048
 
typedef struct sockaddr SA;
 
void commd_ls(int);
void commd_get(int, char *);
void commd_put(int, char *);

char* my_encrypt(char str[], char *path_key);//加密
char* my_decrypt(char str[], char *path_key);//解密

int main(int arg, char *argv[])
{
    int ser_sockfd,cli_sockfd;
    struct sockaddr_in ser_addr,cli_addr;
    int ser_len, cli_len;
    char commd [N];
    bzero(commd,N);//将commd所指向的字符串的前N个字节置为0，包括'\0'
 
    if((ser_sockfd=socket(AF_INET, SOCK_STREAM, 0) ) < 0)
    {
        printf("Sokcet Error!\n");
        return -1;
    }
 
    bzero(&ser_addr,sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);//在TCP连接中，此处类似于自动获取ip地址
                                                //在绑定ip时，自动选择ip地址
    ser_addr.sin_port = htons ( 8989 );
    ser_len = sizeof(ser_addr);
    //将ip地址与套接字绑定
    if((bind(ser_sockfd, (SA *)&ser_addr, ser_len)) < 0)
    {
        printf("Bind Error!\n");
        return -1;
    }
    //服务器端监听
    if(listen(ser_sockfd, 5) < 0)
    {
        printf("Linsten Error!\n");
        return -1;
    }
 
    bzero(&cli_addr, sizeof(cli_addr));
    ser_len = sizeof(cli_addr);
 
    while(1)
    {
        printf("server_ftp>");
        //服务器端接受来自客户端的连接，返回一个套接字，此套接字为新建的一个，并将客户端的地址等信息存入cli_addr中
        //原来的套接字仍处于监听中
        if((cli_sockfd=accept(ser_sockfd, (SA *)&cli_addr, &cli_len)) < 0)
        {
            printf("Accept Error!\n");
            exit(1);
        }
        //由套接字接收数据时，套接字把接收的数据放在套接字缓冲区，再由用户程序把它们复制到用户缓冲区，然后由read函数读取
        //write函数同理
        if(read(cli_sockfd, commd, N) < 0)  //read函数从cli_sockfd中读取N个字节数据放入commd中
        {
            printf("Read Error!\n");
            exit(1);
        }
 
        printf("recvd [ %s ]\n",commd);
 
        if(strncmp(commd,"ls",2) == 0)
        {
            commd_ls(cli_sockfd);
        }else if(strncmp(commd,"get", 3) == 0 )
        {
            commd_get(cli_sockfd, commd+4);
        }else if(strncmp(commd, "put", 3) == 0)
        {
            commd_put(cli_sockfd, commd+4);
        }else
        {
            printf("Error!Command Error!\n");
        }
    }
 
    return 0;
}
 
void commd_ls(int sockfd)
{
    DIR * mydir =NULL;
    struct dirent *myitem = NULL;
    char commd[N] ;
    bzero(commd, N);
    //opendir为目录操作函数，类似于open函数
    //mydir中存有相关目录的信息（有待学习）
    if((mydir=opendir(".")) == NULL)
    {
        printf("OpenDir Error!\n");
        exit(1);
    }
 
    while((myitem = readdir(mydir)) != NULL)
    {
        if(sprintf(commd, myitem->d_name, N) < 0)
        {
            printf("Sprintf Error!\n");
            exit(1);
        }
 
        if(write(sockfd, commd, N) < 0 )
        {
            printf("Write Error!\n");
            exit(1);
        }
    }
 
    closedir(mydir);
    close(sockfd);
 
    return ;
}
 
void commd_get(int sockfd, char *filename)
{
    int fd, nbytes;
    char buffer[N];
    bzero(buffer, N);
    char* ptr_en;

    printf("get filename : [ %s ]\n",filename);
    if((fd=open(filename, O_RDONLY)) < 0)
    {
        printf("Open file Error!\n");
        buffer[0]='N';
        if(write(sockfd, buffer, N) <0)
        {
            printf("Write Error!At commd_get 1\n");
            exit(1);
        }
        return ;
    }
 
    buffer[0] = 'Y';    //此处标示出文件读取成功
    if(write(sockfd, buffer, N) <0)
    {
        printf("Write Error! At commd_get 2!\n");
        close(fd);
        exit(1);
    }
 
    while((nbytes=read(fd, buffer, N)) > 0)
    {
	ptr_en = my_encrypt(buffer,PUBLICKEY);
        if(write(sockfd, ptr_en, strlen(ptr_en)) < 0)
        {
            printf("Write Error! At commd_get 3!\n");
            close(fd);
            exit(1);
        }
    }
 
    close(fd);
    close(sockfd);
 
    return ;
}
 
void commd_put(int sockfd, char *filename)
{
    int fd, nbytes;
    char buffer[N];
    bzero(buffer, N);
    char* ptr_de;
 
    printf("get filename : [ %s ]\n",filename);
    if((fd=open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0)
    {
        printf("Open file Error!\n");
        return ;
    }
 
    while((nbytes=read(sockfd, buffer, N)) > 0)
    {
	ptr_de = my_decrypt(buffer,OPENSSLKEY);
        if(write(fd, ptr_de, strlen(ptr_de)) < 0)
        {
            printf("Write Error! At commd_put 1!\n");
            close(fd);
            exit(1);
        }
    }
 
    close(fd);
    close(sockfd);
 
    return ;
}
char *my_encrypt(char *str, char *path_key) {		//加密函数
	char *p_en;
	RSA *p_rsa;
	FILE *file;
	int flen, rsa_len;
	file = fopen(path_key,"r");
	
	if ((p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)) == NULL) {	//读取公钥
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	flen = strlen(str);				//获取文件大小
	rsa_len = RSA_size(p_rsa);		//获取RSA公钥大小
	p_en = ( char *)malloc(rsa_len + 1);
	memset(p_en, 0, rsa_len + 1);	
	if (RSA_public_encrypt(rsa_len, (unsigned char *)str, (unsigned char*)p_en, p_rsa, RSA_NO_PADDING)<0) {		//进行加密操作
		return NULL;
	}
	RSA_free(p_rsa);		//释放空间
	fclose(file);
	return p_en;
}
char *my_decrypt(char *str, char *path_key) {			//解密函数
	char *p_de;
	RSA *p_rsa;
	FILE *file;
	int rsa_len;
	file = fopen(path_key,"r");
	if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL) {		//获取私钥信息
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	rsa_len = RSA_size(p_rsa);				//获取RSA公钥大小
	p_de = ( char *)malloc(rsa_len + 1);
	memset(p_de, 0, rsa_len + 1);
	if (RSA_private_decrypt(rsa_len, (unsigned char *)str, (unsigned char*)p_de, p_rsa, RSA_NO_PADDING)<0) {		//进行解密
		return NULL;
	}
	RSA_free(p_rsa);		//释放空间
	fclose(file);
	return p_de;
}
