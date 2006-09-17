#include <iostream>
#include <fstream>
#include <string>
#include "sqlite3/sqlite3.h"
using namespace std;

#include "utils.hpp"

sqlite3 *database;
std::ifstream * fpArea;
std::string strArea("help.are");
time_t current_time = time(NULL);

int main(int argc, char** argv) {

  if(sqlite3_open("murk.db", &database)) {
    cerr << "Can't open database: " << sqlite3_errmsg(database) << endl;
    sqlite3_close(database);
    return 1;
  }
  ifstream fp;
  fp.open (strArea.c_str(), ifstream::in | ifstream::binary);
  if (!fp.is_open()) {
    cerr << "Can't find " << strArea << endl;
  }
  for (;;) {
    if (fread_letter (fp) != '#') {
      cerr << "# not found." << endl;
    }
    string word = fread_word (fp);
    if (word[0] == '$')
      break;
    else if (word == "HELPS") {
      for (;;) {
        int level = fread_number (fp);
        string keyword = fread_string (fp);
        if (keyword[0] == '$')
          break;
        string text = fread_string (fp);
        char * z;
        if (text[0] == '.')
          z = sqlite3_mprintf("INSERT INTO 'helps' VALUES(%d,'%q','%q')",
            level, keyword.c_str(), text.substr(1).c_str());
        else
          z = sqlite3_mprintf("INSERT INTO 'helps' VALUES(%d,'%q','%q')",
            level, keyword.c_str(), text.c_str());
        sqlite3_exec(database, z, 0, 0, 0);
        sqlite3_free(z);
      }
    } else {
      cerr << "Load helps: bad section name." << endl;
    }
  }
  fp.close();
  sqlite3_close(database);
  return 0;
}

