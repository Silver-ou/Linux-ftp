#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
 
#define N 256
 
typedef struct sockaddr SA;
 
void commd_help();
void commd_exit();
void commd_ls(struct sockaddr_in, char *);
void commd_get(struct sockaddr_in , char *);
void commd_put(struct sockaddr_in , char *);
 
int main(int argc, char *argv[])
{
    char commd[N];
    struct sockaddr_in addr;
    int len;
    bzero(&addr, sizeof(addr));     //将＆addr中的前sizeof（addr）字节置为0，包括'\0'
    addr.sin_family = AF_INET;      //AF_INET代表TCP／IP协议
    addr.sin_addr.s_addr = inet_addr("127.0.0.1"); //将点间隔地址转换为网络字节顺序
    addr.sin_port = htons(8989);    //转换为网络字节顺序
    len = sizeof(addr);
 
    while(1)
    {
        printf("ftp>");
        bzero(commd,N);
        //fgets函数从stdin流中读取N-1个字符放入commd中
        if(fgets(commd,N,stdin) == NULL)
        {
            printf("Fgets Error!\n");
            return -1;
        }
 
        commd[strlen(commd)-1]='\0';    //fgets函数读取的最后一个字符为换行符，此处将其替换为'\0'
 
        printf("Input Command Is [ %s ]\n",commd);
 
        if(strncmp(commd,"help",4) == 0) //比较两个字符串前4个字节，若相等则返回0
        {
            commd_help();
        }else if(strncmp(commd, "exit",4) == 0)
        {
            commd_exit();
            exit(0);   //结束进程
        }else if(strncmp(commd, "ls" , 2) == 0)
        {
            commd_ls(addr, commd);
        }else if(strncmp(commd, "get" , 3) == 0)
        {
            commd_get(addr, commd);
        }else if(strncmp(commd, "put", 3) ==0 )
        {
            commd_put(addr, commd);
        }else
        {
            printf("Command Is Error!Please Try Again!\n");
        }
 
    }
    return 0;
}
 
void commd_help()
{
 
    printf("\n=------------------- Welcome to Use the Ftp ----------------=\n");
    printf("|                                                           |\n");
    printf("|  help : Display All Command for the Server                |\n");
    printf("|                                                           |\n");
    printf("|   exit: Quit The Sever                                    |\n");
    printf("|                                                           |\n");
    printf("|   ls : Display All file On the Ftp Server                 |\n");
    printf("|                                                           |\n");
    printf("| get <file>: Download FIle from the Ftp Server             |\n");
    printf("|                                                           |\n");
    printf("| put <file>: Upload FIle to the Ftp Server                 |\n");
    printf("|                                                           |\n");
    printf("=-----------------------------------------------------------=\n");
 
    return ;
}
 
void commd_exit()
{
    printf("Byte!\n");
}
 
void commd_ls(struct sockaddr_in addr, char *commd)
{
    int sockfd;
    //创建套接字
    if((sockfd=socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Socket Error!\n");
        exit(1);
    }
 
    if(connect(sockfd, (SA *)&addr, sizeof(addr)) < 0)
    {
        printf("Connect Error!\n");
        exit(1);
    }
    //将commd指向的内容写入到sockfd所指的文件中，此处即指套接字
    if(write(sockfd, commd, N) < 0)
    {
        printf("Write Error!\n");
        exit(1);
    }
 
    while(read(sockfd, commd, N) > 0)  //从sockfd中读取N字节内容放入commd中，
    {                                   //返回值为读取的字节数
        printf(" %s ",commd);
    }
    printf("\n");
 
    close(sockfd);
    return ;
}
/**************************************************/
/*函数功能:实现文件的下载                            */
/**************************************************/
void commd_get(struct sockaddr_in addr, char *commd)
{
    int fd;
    int sockfd;
    char buffer[N];
    int nbytes;
    //创建套接字，并进行错误检测
    if((sockfd=socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Socket Error!\n");
        exit(1);
    }
    //connect函数用于实现客户端与服务端的连接,此处还进行了错误检测
    if(connect(sockfd, (SA *)&addr, sizeof(addr)) < 0)
    {
        printf("Connect Error!\n");
        exit(1);
    }
    //通过write函数向服务端发送数据
    if(write(sockfd, commd, N) < 0)
    {
        printf("Write Error!At commd_get 1\n");
        exit(1);
    }
    //利用read函数来接受服务器发来的数据
    if(read(sockfd, buffer, N) < 0)
    {
        printf("Read Error!At commd_get 1\n");
        exit(1);
    }
    //用于检测服务器端文件是否打开成功
    if(buffer[0] =='N')
    {
        close(sockfd);
        printf("Can't Open The File!\n");
        return ;
    }
    //open函数创建一个文件，文件地址为(commd+4)，该地址从命令行输入获取
    if((fd=open(commd+4, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0)
    {
        printf("Open Error!\n");
        exit(1);
    }
    //read函数从套接字中获取N字节数据放入buffer中，返回值为读取的字节数
    while((nbytes=read(sockfd, buffer, N)) > 0)
    {
        //write函数将buffer中的内容读取出来写入fd所指向的文件，返回值为实际写入的字节数
        if(write(fd, buffer, nbytes) < 0)
        {
            printf("Write Error!At commd_get 2");
        }
    }
 
    close(fd);
    close(sockfd);
 
    return ;
 
}
/**************************************************/
/*函数功能:实现文件的上传                            */
/**************************************************/
void commd_put(struct sockaddr_in addr, char *commd)
{
    int fd;
    int sockfd;
    char buffer[N];
    int nbytes;
    //创建套接字
    if((sockfd=socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Socket Error!\n");
        exit(1);
    }
    //客户端与服务端连接
    if(connect(sockfd, (SA *)&addr, sizeof(addr)) < 0)
    {
        printf("Connect Error!\n");
        exit(1);
    }
    //从commd中读取N字节数据，写入套接字中
    if(write(sockfd, commd, N)<0)
    {
        printf("Wrtie Error!At commd_put 1\n");
        exit(1);
    }
    //open函数从(commd+4)中，读取文件路径，以只读的方式打开
    if((fd=open(commd+4, O_RDONLY)) < 0)
    {
        printf("Open Error!\n");
        exit(1);
    }
    //从fd指向的文件中读取N个字节数据
    while((nbytes=read(fd, buffer, N)) > 0)
    {
        //从buffer中读取nbytes字节数据，写入套接字中
        if(write(sockfd, buffer, nbytes) < 0)
        {
            printf("Write Error!At commd_put 2");
        }
    }
 
    close(fd);
    close(sockfd);
 
    return ;
}