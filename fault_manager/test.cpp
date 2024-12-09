#include <iostream>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
using namespace std;

int main() {
	int server_coid;
	cout << "Hello World!!!" << endl;
	server_coid = open("/dev/fault_manager", O_RDWR);
	if (server_coid == -1) {
		cout << "Fault manager can't be opened" << endl;
		return EXIT_FAILURE;
	}
	MsgSendPulse(server_coid, -1, 15, 0x44);

	close(server_coid);

	return 0;
}
