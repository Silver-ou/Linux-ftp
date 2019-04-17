#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#include <openssl/applink.c>
 
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#define TEXT "C://hello.txt"			//所要加密的文件
#define OPENSSLKEY "C://test.key"    //文件为Openssl生成的密钥文件
#define PUBLICKEY "C://test_pub.key"
#define BUFFSIZE 1024
#define MAXLINE 2048

char* my_encrypt(char str[], char *path_key);//加密
char* my_decrypt(char str[], char *path_key);//解密

int main() {

	//从文件中获取文件内容，并保存

	char str[MAXLINE];
	FILE *file;
	fopen_s(&file, TEXT, "r");
	fgets(str,MAXLINE,file);
	fclose(file);

	char *ptr_en, *ptr_de;
	printf("source is    :%s\n", str);  //输出原文件内容
	ptr_en = my_encrypt(str, PUBLICKEY);
	printf("after encrypt:%s\n", ptr_en);  //输出加密后的文件内容

	FILE *file2;
	fopen_s(&file2, "C:\\AfterEncrypt.txt", "w");
	fprintf(file2,ptr_en,MAXLINE);
	fclose(file2);

	ptr_de = my_decrypt(ptr_en, OPENSSLKEY);
	printf("after decrypt:%s\n", ptr_de);	//输出解密后的文件内容

	//写文件
	FILE *file1;
	fopen_s(&file1, "C:\\AfterDecrypt.txt", "w");
	fprintf(file1,ptr_de,MAXLINE);
	fclose(file1);

	if (ptr_en != NULL) {
		free(ptr_en);				//释放空间
	}
	if (ptr_de != NULL) {
		free(ptr_de);
	}
	system("pause");
	return 0;
}
char *my_encrypt(char *str, char *path_key) {		//加密函数
	errno_t err;
	char *p_en;
	RSA *p_rsa;
	FILE *file;
	int flen, rsa_len;
 
 
	if ((err = fopen_s(&file, path_key, "r")) != 0) {		//打开公钥文件
		perror("open key file error");
		return NULL;
	}
	
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
	errno_t err;
	char *p_de;
	RSA *p_rsa;
	FILE *file;
	int rsa_len;
	if (( err= fopen_s(&file,path_key, "r"))!=0) {		//打开私钥文件
		perror("open key file error");
		return NULL;
	}
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