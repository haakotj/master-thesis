# master-thesis

A modified ChaCha20-Poly1305 with two key parts: one MAC key and one confidentiality key. This allows for authenticated encryption, authenticated decryption, and a separate integrity validation. 

The files:
* **ChaCha20_poly1305_modified.py:** contain a python implementation of the modified chacha20-poly1305
* **Simulation_chacha20-poly1305_modified_scenario1.py:** simulation of the modified chacha20-poly1305 in the cloud-IoT architecture
* **Simulation_chacha20-poly1305_modified_scenario2.py:** simulation of the modified chacha20-poly1305 in the cloud-IoT architecture with attacker modifying the ciphertext during transmission
* **Simulation_chacha20-poly1305_modified_scenario3.py:** simulation of the modified chacha20-poly1305 in the cloud-IoT architecture where the end-user receives wrong authentication tag

For the simulation, Simpy was used (https://simpy.readthedocs.io/en/latest/). Three scenarios was considered. 
* Scenario 1: Data is sent from the sensor to the end-user via the cloud. The sensor performs authenticated encryption and sends the packet to the cloud. The cloud verifies the message with the MAC key and sends it to the end-user, performing authenticated decryption. This is the desired flow. 
* Scenario 2: Data is sent from the sensor to the end-user via the cloud. An attacker performs a \gls{mitm} attack between the sensor and the cloud and modifies the ciphertext. The cloud is not able to verify the integrity and discards the message. 
* Scenario 3: Data is sent from the sensor to the end-user via the cloud. The authentication tag is changed between the cloud and the end-user. The end-user cannot verify the integrity when decrypting and discards the message.


The implementation is based on RFC8439 and D. J. Bernstein documentations. 

## References:
* RFC 8439 (https://datatracker.ietf.org/doc/html/rfc8439)
* D. J. Bernstein ChaCha20 documentation (https://cr.yp.to/chacha.html  
* D. J. Bernstein Poly1305 documentation https://cr.yp.to/mac.html)
* https://github.com/Ginurx/chacha20-c
* https://github.com/tex2e/chacha20-poly1305
* https://github.com/pts/chacha20
* https://gist.github.com/cathalgarvey/0ce7dbae2aa9e3984adc
