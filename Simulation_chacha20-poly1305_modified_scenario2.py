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
    plaintext = b'Confidential message!'
    ad = b'This is AD'

    #Authenticated encryption:
    ciphertext, tag = chaCha20_poly1305_authenticated_encryption(integrity_key, encryption_key, nonce, plaintext, ad)
    
    #Illustrate the message as a dictionary where the data is shown as hexadecimal
    content = [nonce.hex(), ad.hex(), ciphertext.hex(), tag.hex()]
    result = json.dumps(dict(zip(type, content)))    
    print('%s sends the following message at time %d: %s' % (name, env.now, result)+"\n")
    out_pipe.put(result) 


def attacker_modifying_message(name, env, in_pipe, out_pipe2):
    yield env.timeout(40)
    msg_receieved = yield in_pipe.get()
    print('%s receives the following message at time %d: %s'  % (name, env.now,msg_receieved))
    msg = json.loads(msg_receieved)
    byte_msg = {k: unhexlify(msg[k]) for k in type}
    yield env.timeout(10)

    #Attacker changing the ciphertext 
    new_cipher = get_random_bytes(12)
    content = [byte_msg['nonce'].hex(), byte_msg['header'].hex(), new_cipher.hex(), byte_msg['tag'].hex()]
    new_msg = json.dumps(dict(zip(type, content)))
    print('%s tampers and sends the following message at time %d: %s' % (name, env.now, new_msg)+"\n")
    out_pipe2.put(new_msg)
    


def cloud_receive(name, env2, in_pipe2, out_pipe3):
    yield env2.timeout(80)
    msg_receieved1 = yield in_pipe2.get()
    print('%s receives the following message at time %d: %s'  % (name, env2.now,msg_receieved1))
    
    #Cloud only possesses the MAC-key:
    integrity_key = integrity_key_random
    msg = json.loads(msg_receieved1)
    byte_msg = {k: unhexlify(msg[k]) for k in type}

    #Verification of MAC-tag:
    if chaCha20_poly1305_authenticate_only(integrity_key,byte_msg['nonce'], byte_msg['ciphertext'], byte_msg['tag'],byte_msg['header']):
        env2.succeed()
        print("Message is verified by cloud")
        yield env2.timeout(20)
        print('%s sends the following message at time %d: %s' % (name, env2.now, msg_receieved1)+"\n")
        out_pipe3.put(msg_receieved1)
    else:
        SIM_TIME = 0
        print("Message not verified. Message discarded")
        


def consumer_receive(name, env3, in_pipe3):
    yield env3.timeout(100)
    msg_receieved2 = yield in_pipe3.get()
    print('%s receives the following message at time %d: %s' % (name, env3.now, msg_receieved2))
    integrity_key = integrity_key_random
    encryption_key = encryption_key_random

    msg = json.loads(msg_receieved2)
    byte_msg = {k: unhexlify(msg[k]) for k in type}

    #Authenticated decryption:
    chaCha20_poly1305_authenticated_decryption(integrity_key,encryption_key,byte_msg['nonce'], byte_msg['ciphertext'], byte_msg['tag'],byte_msg['header'])
   


print('Process communication:')
env = simpy.Environment()
pipe = simpy.Store(env)
env2 = simpy.Environment()
pipe2 = simpy.Store(env2)
env3 = simpy.Environment()
pipe3 = simpy.Store(env3)



env.process(sensor('SENSOR', env, pipe))
env.process(attacker_modifying_message('ATTACKER', env, pipe, pipe2))
env2.process(cloud_receive('CLOUD', env2, pipe2, pipe3))
env3.process(consumer_receive('CONSUMER', env3, pipe3))
env.run(until=SIM_TIME)
env2.run(until=SIM_TIME)
env3.run(until=SIM_TIME)