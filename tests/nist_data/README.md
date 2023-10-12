- These testing cases comes from NIST website: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
- The total number of tests can be found by counting all "Count" keywords in all .rsp files. Since OFB is not supported yet, files with name containing "OFB" are filtered out. For example:
    `find . -name "*.rsp" | grep -v "OFB" | xargs cat | grep -i "count" | wc -l`
The result is 63820, i.e., there are 63820 tests in total.
