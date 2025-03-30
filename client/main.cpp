#include "ui.h"
//#include "data_handler.h"
#include "client.h"
#include "show_error.h"
#include "error.h"
int main(int argc, char* argv[])
{
    try{
        UI interface (argc,argv);
        client CL;
        CL.work(interface);
        /*data_handler handler;
        handler.read_data_from_file(interface.get_in_file_location());
        handler.communication_with_server(CL);
        handler.write_result_to_file(interface.get_out_file_location());*/
    }catch (po::error& e) {
        std::cout << e.what() << std::endl;
    }
    catch(client_error &e){
        std::cout<<"Критическая ошибка: "<<e.what()<<std::endl;
    }
    return 0;
}
