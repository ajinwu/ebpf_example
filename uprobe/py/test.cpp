#include <iostream>
#include <unistd.h>

class Test {
    public:
    int a;
};

int saySomething(Test* test, int c){
    std::cout << "test.a: " << test->a << "  param2: "<< c << std::endl; 
    return 100;
}

int main(){
    Test test1;
    test1.a = 2;
    while (true) {
        std::cout << "Ret: " << saySomething(&test1, 5) << std::endl;
        sleep(1);
    }
    return 0;
}
