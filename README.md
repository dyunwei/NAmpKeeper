# NAmpKeeper
NAmpKeeper is a novel structure designed to store valid non-amplifiers. DNS queries to and DNS responses from valid non-amplifiers are considered as safe DNS packets. By directly forwarding safe queries and responses between the victim and valid non-amplifiers, resulting in a reduction of the number of elements in Two-Bloom filter, which in turn minimizes false positives significantly. As a result, our goal of improve filtering malicious DNS responses is achieved.

# Two-Bloom filter
Two-Bloom filter comprises of two Bloom filters, which alternate in storing DNS queries within a predefined time interval $\delta$ (e.g., $\delta=2$ seconds).


