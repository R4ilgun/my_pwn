#include <stdio.h> 
int main()
{
double x=0.1; 
long long n = *(long long*)&x;
printf("%llX",n);
}

