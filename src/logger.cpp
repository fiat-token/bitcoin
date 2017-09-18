#include <fstream>
#include <string>

class Logger
{
    private:
        std::string logFile = "logkal.log";
        
    public:
        Logger() {};
        Logger(std::string file) : logFile(file) {};

        bool write(std::string data)
        {
            std::ofstream outfile;
            outfile.open(logFile, std::ios_base::app);
            if(!outfile.is_open()) return false;
            outfile << data << "\n";
            return true;
        }

        bool write(unsigned char& data)
        {
            std::ofstream outfile;
            outfile.open(logFile, std::ios_base::app);
            if(!outfile.is_open()) return false;
            outfile << data << "\n";
            return true;
        }
};
