# NAmpKeeper
NAmpKeeper is a novel structure designed to store valid non-amplifiers. DNS queries to and DNS responses from valid non-amplifiers are considered as safe DNS packets. By directly forwarding safe queries and responses between the victim and valid non-amplifiers, resulting in a reduction of the number of elements in Two-Bloom filter, which in turn minimizes false positives significantly. As a result, our goal of improve filtering malicious DNS responses is achieved.

# Two-Bloom filter
We use Two-Bloom filter, denoted as an array BF[2], to mitigate unsolicited DNS responses. Two-Bloom filter comprises of two Bloom filters, BF[0] and BF[1], which alternate in storing DNS queries within a predefined time interval $\delta$ (e.g., $\delta=2$ seconds).

# Datasets
We provide sample datasets [here](https://drive.google.com/drive/folders/184Ln8ps5dK93xV_In23Z1FkJM8NjFV1b?usp=sharing). You can download and put the whole folder in the working directory for testing.

# Compile
* Compile to get the excutable file for BF+
  ```
  ./make
  ```
* Compile to get the excutable file for BF
  ```
  ./make CXXFLAGS=-D=BF
  ```

# Run
* The program will output logs in the `stats` directory and result files in the `stats/temp` directory.
* Below is an example of an experiment on the MAWI dataset.
  ```
  ./bin/DAmpADF dataset/mawi/2019/background_traffic.csv 1 dataset/cic2019/attack_traffic.csv 4 4 0 2019 ./
  ```
* Below is an example of an experiment on the Zipf dataset.
   ```
   ./bin/DAmpADF dataset/zipf/test-s-0.6-3-1 0 dataset/cic2019/attack_traffic.csv 100 200 0 ZTEST ./
   ```
# Usage
* using `-h` to get help information:
```
Usage:
	bin/DAmpADF Background_Traffic_File Is_MAWI_Dataset Attack_Traffic_File  Mem_For_NAmpKeeper 
                    Mem_For_Bloomfilter AmplifierIP Label WorkingDirectory

1. Background_Traffic_File: Path to the DNS background traffic file, e.g.: dataset/mawi/2019/background_traffic.csv.
2. Is_MAWI_Dataset        : Enter 1 if it is a MAWI dataset.
3. Attack_Traffic_File    : Path to the attack traffic file, e.g.: dataset/cic2019/attack_traffic.csv.
4. Mem_For_NAmpKeeper     : Memory size in KiB for NAmpKeeper.
5. Mem_For_Bloomfilter    : Memory size in KiB for TwoBloomFilter.
6. AmplifierIP            : IP to replace the amplifier IP in the attack file, Enter 0 if you don't want to replace it.
7. Label                  : Label for the result file.
8. WorkingDirectory       : Path to the working directory.
```

