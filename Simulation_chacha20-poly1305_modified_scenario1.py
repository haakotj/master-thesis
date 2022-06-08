from Crypto.Random import get_random_bytes
import simpy
import json
from binascii import unhexlify
from ChaCha20_Poly1305_modified import *


SIM_TIME = 1000
type = ['nonce', 'header', 'ciphertext', 'tag']
#256-bit MAC-key:
integrity_key_random = get_random_bytes(32)
#256-bit confidentiality-key:
encryption_key_random = get_random_bytes(32)
#96-bit nonce:
nonce_random = get_random_bytes(12)


def sensor(name, env, out_pipe):
    yield env.timeout(10)
    integrity_key = integrity_key_random
    encryption_key = encryption_key_random
    nonce = nonce_random
    plaintext = b'This message is confidential!'
    ad = b'This is AD'

    #Authenticated encryption:
    ciphertext, tag = chaCha20_poly1305_authenticated_encryption(integrity_key, encryption_key, nonce, plaintext, ad)
    
    #Illustrate the message as a dictionary where the data is displayed as hexadecimal
    content = [nonce.hex(), ad.hex(), ciphertext.hex(), tag.hex()]
    result = json.dumps(dict(zip(type, content)))
    print('%s sends the following message at time %d: %s' % (name, env.now, result)+"\n")
    out_pipe.put(result) 

def cloud_receive(name, env, in_pipe, out_pipe2):
    yield env.timeout(20)
    msg_receieved = yield in_pipe.get()
    print('%s receives the following message at time %d: %s'  % (name, env.now,msg_receieved))
    
    #Cloud only possesses the MAC-key:
    integrity_key = integrity_key_random
    msg = json.loads(msg_receieved)
    byte_msg = {k: unhexlify(msg[k]) for k in type}
    
    #Verification of MAC-tag:
    if chaCha20_poly1305_authenticate_only(integrity_key,byte_msg['nonce'], byte_msg['ciphertext'], byte_msg['tag'],byte_msg['header']):
        print("Message is verified by cloud")
        yield env.timeout(20)
        print('%s sends the following message at time %d: %s' % (name, env.now, msg_receieved)+"\n")
        out_pipe2.put(msg_receieved)
    else:
        SIM_TIME = 0
        print("Message not verified. Message discarded")


def consumer_receive(name, env2, in_pipe2):
    yield env2.timeout(60)
    msg_receieved = yield in_pipe2.get()
    integrity_key = integrity_key_random
    encryption_key = encryption_key_random
    print('%s receives the following message at time %d: %s' % (name, env2.now, msg_receieved))
    
    msg = json.loads(msg_receieved)
    byte_msg = {k: unhexlify(msg[k]) for k in type}
    
    #Authenticated decryption:
    chaCha20_poly1305_authenticated_decryption(integrity_key,encryption_key,byte_msg['nonce'], byte_msg['ciphertext'], byte_msg['tag'],byte_msg['header'])
   

print('Process communication:')
env = simpy.Environment()
pipe = simpy.Store(env)
env2 = simpy.Environment()
pipe2 = simpy.Store(env2)


env.process(sensor('SENSOR', env, pipe))
env.process(cloud_receive('CLOUD', env, pipe, pipe2))
env2.process(consumer_receive('CONSUMER', env2, pipe2))
env.run(until=SIM_TIME)
env2.run(until=SIM_TIME)

