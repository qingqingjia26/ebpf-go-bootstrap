#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define DEST_IP "127.0.0.1"  // 目标 IP 地址
#define DEST_PORT 8888       // 目标端口号
#define BUF_SIZE 1024        // 缓冲区大小

int func()
{
	int sockfd;
	struct sockaddr_in dest_addr;
	char buf[BUF_SIZE];

	// 创建 UDP 套接字
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	// 设置目标地址信息
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(DEST_PORT);
	dest_addr.sin_addr.s_addr = inet_addr(DEST_IP);

	// 构造要发送的数据
	strcpy(buf, "Hello, this is a test message!");

	// 发送数据包
	if (sendto(sockfd, buf, strlen(buf), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
		perror("sendto");
		close(sockfd);
		exit(1);
	}

	printf("Data sent successfully.\n");

	// 关闭套接字
	close(sockfd);
	return 0;
}

int func1()
{
	func();
}

int func2()
{
	func1();
}

int func3()
{
	func2();
}

int main()
{
	while (1) {
		func3();
		sleep(1);
	}
	return 0;
}