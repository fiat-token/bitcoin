#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <vector>
#include <map>

class Parameters
{
  public:
    std::map<std::string, std::string> get(std::string filename)
    {
      std::ifstream myfile;
      myfile.open(filename);

      // if(!myfile.is_open()) return "cannot open file conf"; // throw error

      std::string line;
      std::map<std::string, std::string> mapResult;
      while(std::getline(myfile, line))
      {
        std::vector<std::string> keyAndValue = split(line, "=");
        mapResult[keyAndValue[0]] = keyAndValue[1];
      }
      myfile.close();

      for(auto it = mapResult.begin(); it != mapResult.end(); ++it)
      {
          std::cout << it->first <<  " -> " << it->second[0] << "\n";
      }
      return mapResult;
    }

    std::vector<std::string> split(std::string strToBeSplitted, std::string pattern)
    {
      std::regex regex(pattern);
      std::vector<std::string> result { std::sregex_token_iterator(strToBeSplitted.begin(), strToBeSplitted.end(), regex, -1), {} };
      return result;
    }
};
