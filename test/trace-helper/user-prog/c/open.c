#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

int func()
{
    char path[PATH_MAX/2];
    char *last_slash;
    ssize_t len;
    int fd;

    // Get the path of the current program
    len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1) {
        printf("Unable to get program path.\n");
        return 1;
    }

    path[len] = '\0';

    // Find the last slash, which denotes the end of the file path
    last_slash = strrchr(path, '/');
    if (last_slash == NULL) {
        printf("Unable to get file path.\n");
        return 1;
    }

    // Terminate the string at the last slash to get the file path
    *last_slash = '\0';

    // Print the file path and file name
    printf("Current file path: %s\n", path);
    printf("Current file name: %s\n", last_slash + 1);

    // Concatenate the file path and file name
    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), "%s/%s", path, last_slash + 1);

    // Open the file using open()
    fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        printf("Unable to open the file.\n");
        return 1;
    }

    // File operations

    // Close the file
    close(fd);
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