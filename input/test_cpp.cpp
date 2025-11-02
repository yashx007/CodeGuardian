#include <stdio.h>
#include <string.h>

int main() {
    char buf[10];
    strcpy(buf, "this is too long and will overflow");
    system("ls -la");
    const char *password = "cpp_password_123";
    return 0;
}
