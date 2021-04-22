#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <numeric>
#include <iterator>

// Distance between 2 strings
size_t levensthein(const std::string& string1, const std::string& string2)
{
    // First get the string lengths
    const size_t lengthString1{ string1.size() };
    const size_t lengthString2{ string2.size() };

    // If one of the string length is 0, then return the length of the other
    // This results in 0, if both lengths are 0
    if (lengthString1 == 0) return lengthString2;
    if (lengthString2 == 0) return lengthString1;

    // Initialize substitition cost vector
    std::vector<size_t> substitutionCost(lengthString2 + 1);
    std::iota(substitutionCost.begin(), substitutionCost.end(), 0);

    // Calculate substitution cost
    for (size_t indexString1{}; indexString1 < lengthString1; ++indexString1) {
        substitutionCost[0] = indexString1 + 1;
        size_t corner{ indexString1 };

        for (size_t indexString2{}; indexString2 < lengthString2; ++indexString2) {
            size_t upper{ substitutionCost[indexString2 + 1] };
            if (string1[indexString1] == string2[indexString2]) {
                substitutionCost[indexString2 + 1] = corner;
            }
            else {
                const size_t temp = std::min(upper, corner);
                substitutionCost[indexString2 + 1] = std::min(substitutionCost[indexString2], temp) + 1;
            }
            corner = upper;
        }
    }
    return substitutionCost[lengthString2];
}

// Put in your filenames here
const std::string fileName1{ "tmp1" };
const std::string fileName2{ "tmp2" };

int main() {

    // Open first file and check, if it could be opened
    if (std::ifstream file1Stream{ fileName1 }; file1Stream) {

        // Open second file and check, if it could be opened
        if (std::ifstream file2Stream{ fileName2 }; file2Stream) {

            // Both files are open now, read them into strings
            std::string stringFile1(std::istreambuf_iterator<char>(file1Stream), {});
            std::string stringFile2(std::istreambuf_iterator<char>(file2Stream), {});

            // Show Levenstehin distance on screen
            std::cout << "Levensthein distance is: " << levensthein(stringFile1, stringFile2) << '\n';
        }
        else {
            std::cerr << "\n*** Error. Could not open input file '" << fileName2 << "'\n";
        }
    }
    else {
        std::cerr << "\n*** Error. Could not open input file '" << fileName1 << "'\n";
    }
    return 0;

}
