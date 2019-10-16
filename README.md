# Project:           Implementation and Evaluation of Low-Latency Key-Exchange Protocols (Bloom Filter Encryption C Implementation)

## Documentation

### Build Instructions
To successfully build the BFE library, RELIC library has to be installed. Detailed instructions can be found [here](https://github.com/relic-toolkit/relic/wiki/Building). Brief installation steps are following:
1.  Extract the RELIC archive to a `relic-<version>` directory.
2.  Create a target directory: `mkdir relic-target`.
3.  Run `cmake` inside a target directory: `cd relic-target; cmake ../relic-<version> -DFP_PRIME=<field_size>` where `field_size` can be one of the values defined in [relic_ep.h](https://github.com/relic-toolkit/relic/blob/master/include/relic_ep.h), e.g. for *BN_P382* we write `-DPF_PRIME=382`.
4.  Run `make install`.

After RELIC library is installed, to install the BFE library:
1. Checkout the repository to a `bfe-<version>` directory.
2. Create a target directory: `mkdir bfe-target`.
3. Run `cmake` inside a target directory: `cd bfe-target; cmake ../bfe-<version>`.
4. Run `make install`.

## Status
### TODO
1. Clean up and reorganize test.c file to a usage example file
