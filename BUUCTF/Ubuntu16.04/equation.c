#include <stdio.h>

int main(){
    int format = 0;
    for(int judge=0;judge<=10;judge++){
        format = 11 * judge * judge + 17 * judge * judge * judge * judge - 13 * judge * judge * judge - 7 * judge;
        if(format==198){
            printf("%d,success\n",judge);
        }else{
            printf("%d---->%d\n",judge,format);
        }
    }

}
