# master-thesis

The modified ChaCha20-Poly1305 with two keys: one MAC key and one confidentiality key. 
The implementation is based on RFC8439 and D. J. Bernstein documentations. 


The files:
* **ChaCha20_poly1305_modified.py:** contain a python implementation of the modified chacha20-poly1305
* **Simulation_chacha20-poly1305_modified_scenario1.py:** simulation of the modified chacha20-poly1305 in the cloud-IoT architecture
* **Simulation_chacha20-poly1305_modified_scenario2.py:** simulation of the modified chacha20-poly1305 in the cloud-IoT architecture with attacker modifying the ciphertext during transmission
* **Simulation_chacha20-poly1305_modified_scenario3.py:** simulation of the modified chacha20-poly1305 in the cloud-IoT architecture where the end-user receives wrong authentication tag


## References:
* RFC 8439 (https://datatracker.ietf.org/doc/html/rfc8439)
* D. J. Bernstein ChaCha20 documentation (https://cr.yp.to/chacha.html  
* D. J. Bernstein Poly1305 documentation https://cr.yp.to/mac.html)
* https://github.com/tex2e/chacha20-poly1305
* https://github.com/pts/chacha20
* https://gist.github.com/cathalgarvey/0ce7dbae2aa9e3984adc
