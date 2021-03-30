#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <cstdlib>
#include <cassert>
using namespace std;
struct StackTrace{
    vector<string> trace;
    string key; 
    string testcase;
};
int main(int argc, char *argv[]){

    map<string, StackTrace> stack_traces;

    if (argc < 3){
        cout << "Usage: " << argv[0] << " input_file output_fille " << endl;
        return 0;
    }

    ofstream out(argv[2]);
    if (!out){
        cout << "Failed to open " << argv[2] << endl;
        return 0;
    }


    ifstream in(argv[1]);
    if (!in){
        cout << "Failed to open " << argv[1] << endl;
        return 0;
    }

    bool is_in_trace = false;
    StackTrace *trace = NULL;
    int linenum = 0;

    string machine;
    while(!in.eof()){
        string line;
        getline(in, line); 
        linenum++;


        //cout << "line: " << linenum << endl;

        
        if (line.find("SUCCESS") != string::npos) {
          machine = line.substr(line.rfind(" ") + 1);
        } else if (line.rfind("TRACE ", 0) == 0 ){
            if (is_in_trace){
                assert(trace != NULL);
                stack_traces[trace->key] = *trace;
                delete trace; 
                trace = NULL;
            }
            string testcase;
            getline(in, testcase);
            linenum++;
            is_in_trace = true;
            assert(trace == NULL);
            testcase = machine + ":/home/cheong/" + testcase;
            trace = new StackTrace();
            trace->testcase = testcase; 

        }else if ((line.rfind("b'#", 0) == 0) || (line.rfind("b\"#", 0) == 0)){
            assert(is_in_trace == true);
            assert(trace != NULL);
            string source_loc(line.substr(line.rfind(" ") + 1));
            trace->key += source_loc;
            trace->trace.push_back(line);
        }else{
            if (is_in_trace){
                assert(trace != NULL);
                stack_traces[trace->key] = *trace;
                delete trace;
                trace = NULL;
                is_in_trace = false;
            }
        }
    }
    in.close();
    
   
    
    out << "# of stacks : " << stack_traces.size() << endl;
    for (auto i = stack_traces.begin(); i != stack_traces.end(); ++i){
        StackTrace trace = i->second;
        out << "TESTCASE:" << trace.testcase << endl;
        for (auto j = trace.trace.begin(); j != trace.trace.end(); ++j){
            out << *j << endl;
        }
        out << "STACKEND" << endl;
    }
    out.close();
    
    return 0;
}

