- These testing cases comes from NIST website: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
- The total number of tests can be found by counting all "Count" keywords in all .rsp files. Since CFB and OFB are not supported, files with name containing them are filtered out. For example:
    `find . -name "*.rsp" | grep -v "CFB" | grep -v "OFB" | xargs cat | grep -i "count" | wc -l`
The result is 55606, i.e., there are 55606 tests in total.
