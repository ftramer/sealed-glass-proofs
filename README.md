
Implementation of proofs of bug exploits using Intel SGX, as described in the following paper:


**Sealed-Glass Proofs: Using Transparent Enclaves to Prove and Sell Knowledge**  
*Florian Tramèr, Fan Zhang, Huang Lin, Jean-Pierre Hubaux, Ari Juels and Elaine Shi*  
European Symposium on Security and Privacy, 2017 (EuroS&P'17).

<br>

###### REQUIREMENTS

The code was developed and tested using Visual Studio 2012 on an SGX equipped machine.

The main enclave program is defined in ZK-Enclave, and contains the boilerplate code for setting up an exploit environment, checking that the exploit runs correctly, and finally encrypting the exploit and signing it.

To compile the ZK-Enclave project, the ``run'' method (defined in Prog.h) has to implemented. Two examples are provided in the SQLInjection project (to test a SQL Injection exploit on a user login form) and the DiffTesting project (to test for discrepancies in X.509 certificate validation). Either of these projects has to be statically linked with ZK-Enclave.

The code to set up the enclave and call it with a given exploit is in the App project.

###### CONTACT

Questions and suggestions can be sent to florian.tramer@gmail.com 