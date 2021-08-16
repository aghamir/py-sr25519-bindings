import os

import sr25519_nbx
from substrateinterface import Keypair


x1_mnemonic = 'stone cereal magnet search zoo split dish leisure crouch uniform elite panic'
x2_mnemonic = 'diagram truck orient actress resource attitude you initial during slight actress cluster'
x1_kp = Keypair.create_from_mnemonic(x1_mnemonic)
x2_kp = Keypair.create_from_mnemonic(x2_mnemonic)

p = 2**255-19
l = 2**252 + 27742317777372353535851937790883648493
print('x1_priv = ', x1_kp.private_key[2:66])
print('x1_pub = ', x1_kp.public_key)


publickey_sum = sr25519_nbx.sum_public_points(bytes.fromhex(x1_kp.public_key[2:]), bytes.fromhex(x2_kp.public_key[2:]))
print(publickey_sum.hex())

x1 = int.from_bytes(bytes.fromhex(x1_kp.private_key[2:66]), 'little')
x2 = int.from_bytes(bytes.fromhex(x2_kp.private_key[2:66]), 'little')

k1 = int.from_bytes(os.urandom(32), 'big') % l
R1 = sr25519_nbx.public_from_secret_key(k1.to_bytes(32, 'little') + bytes.fromhex('44' * 32))

k2 = int.from_bytes(os.urandom(32), 'big') % l
R2 = sr25519_nbx.public_from_secret_key(k2.to_bytes(32, 'little') + bytes.fromhex('44' * 32))

R = sr25519_nbx.sum_public_points(R1, R2)

x_gold = (x1 + x2) % l

p_gold = sr25519_nbx.public_from_secret_key(x_gold.to_bytes(32, 'little') + bytes.fromhex('33' * 32))

print(p_gold.hex())
data = bytes.fromhex('33445566')

sig1 = sr25519_nbx.multi_sign((p_gold, bytes.fromhex(x1_kp.private_key[2:])),
                          data,
                          R,
                          k1.to_bytes(32, 'little') + bytes.fromhex('44' * 32))
sig2 = sr25519_nbx.multi_sign((p_gold, bytes.fromhex(x2_kp.private_key[2:])),
                          data,
                          R,
                          k2.to_bytes(32, 'little') + bytes.fromhex('44' * 32))
print('sig1', sig1.hex())
print('sig2', sig2.hex())
s_gold = (int.from_bytes(sig1[32:], 'little') + int.from_bytes(sig2[32:], 'little')) % l
s_gold_bytes = s_gold.to_bytes(32, 'little')
sig_gold = R + s_gold_bytes[:31] + (int(s_gold_bytes[31]) | 128).to_bytes(1,'little')
print('sigG', sig_gold.hex())
ver_gold = sr25519_nbx.verify(sig_gold, data, p_gold)

print(ver_gold)
exit()
