# CryptoBench-InfiniBand


CryptoBench provides secure inter-node communication in the HPC cluster and cloud environment. 
We develop encrypted MPI libraries that are built on top of four cryptographic libraries:
1- OpenSSL
2- BoringSSL
3- Libsodium
4- CryptoPP

All of these cryptographic libraries designed based on GCM approach and only are different in implantation. Using these libraries, I empirically evaluate the performance of encrypted MPI communications with micro benchmarks and NAS parallel benchmarks on two networking technologies, 10Gbps Ethernet and 40Gbps InfiniBand QDR
