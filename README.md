# NAmpKeeper
NAmpKeeper is a novel structure designed to store valid non-amplifiers. DNS queries to and DNS responses from valid non-amplifiers are considered as safe DNS packets. By directly forwarding safe queries and responses between the victim and valid non-amplifiers, resulting in a reduction of the number of elements in Two-Bloom filter, which in turn minimizes false positives significantly. As a result, our goal of improve filtering malicious DNS responses is achieved.

A two-mode Active Counter is used to expand the ranges of counters. The two modes are the normal mode and exponential mode. In the normal mode, indicated by a leftmost bit of 0, the counter's maximum value is 127 (01111111). In the exponential mode, the counter consists of a coefficient part (denoted as $\alpha$) and an exponent part (denoted as $\beta$). The counter's value is calculated as $\alpha \times 2^{\beta+\gamma}$, where $\gamma$ represents the length of $\beta$. For example, while allocating 5 bits for the coefficient part and 3 bits for the exponent part, the counter can count up to 31,774 (i.e., $31 \times 2^{3+7}$) DNS queries or DNS responses.

# Two-Bloom filter
We use Two-Bloom filter, denoted as an array BF[2], to mitigate unsolicited DNS responses. Two-Bloom filter comprises of two Bloom filters, BF[0] and BF[1], which alternate in storing DNS queries within a predefined time interval $\delta$ (e.g., $\delta=2$ seconds).


