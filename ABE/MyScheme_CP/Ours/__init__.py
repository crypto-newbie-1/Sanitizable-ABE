'''
Doreen Riepel, Hoeteck Wee

| From: "FABEO: Fast Attribute-Based Encryption with Optimal Security"
| Published in: 2022
|
| type:           Modified to support Sanitization and Outsourced Decryption
| setting:        Pairing

:Authors:         zhiyixu
:Date:            03/2026
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False

class FABEO22CPABE(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "FABEO CP-ABE"
        self.group = group_obj
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)
        
        alpha = self.group.random(ZR)

        # now compute various parts of the public parameters
        e_gh_alpha = e_gh ** alpha

        # the master secret and public key
        msk = {'alpha': alpha}
        pk = {'g': g, 'h': h, 'e_gh_alpha': e_gh_alpha}

        return pk, msk

    def keygen(self, pk, msk, attr_list):
        """
        Generate a key for a list of attributes.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        r = self.group.random(ZR)
        h_r = pk['h'] ** r

        sk1 = {}
        for attr in attr_list:
            attrHash = self.group.hash(attr, G1)
            sk1[attr] = attrHash ** r
        
        bHash = self.group.hash(str(self.group.order()+1), G1) # ZR+1
        
        sk2 = pk['g'] ** msk['alpha'] * bHash ** r

        return {'attr_list': attr_list, 'h_r': h_r, 'sk1': sk1, 'sk2': sk2}

    def keygen_out(self, sk):
        """
        Delegate the costly decryption operations by creating a transformation key.
        """

        if debug:
            print('\nKeyGen_out algorithm:\n')

        # pick transformation factor z
        z = self.group.random(ZR)
        
        # transform secret key components
        tk_h_r = sk['h_r'] ** z
        tk_sk2 = sk['sk2'] ** z
        
        tk_sk1 = {}
        for attr, key_val in sk['sk1'].items():
            tk_sk1[attr] = key_val ** z
            
        tk = {'attr_list': sk['attr_list'], 'h_r': tk_h_r, 'sk1': tk_sk1, 'sk2': tk_sk2}
        dk = z

        return tk, dk

    def encrypt(self, pk, msg, policy_str):
        """
        Encrypt a message msg under a policy string.
        """

        if debug:
            print('\nEncryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        s0 = self.group.random(ZR)
        s1 = self.group.random(ZR)

        g_s0 = pk['h'] ** s0
        h_s1 = pk['h'] ** s1 
        
        # pick random shares
        v = [s0]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)
        
        bHash = self.group.hash(str(self.group.order()+1), G1) # ZR+1

        ct = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            ct[attr] = bHash ** Mivtop * attrHash ** s1
            
        # compute the e(g, h)^(As) * m term
        Cp = pk['e_gh_alpha'] ** s0
        Cp = Cp * msg

        return {'policy': policy, 'g_s0': g_s0, 'h_s1': h_s1, 'ct': ct, 'Cp': Cp}

    def sanitize(self, pk, ctxt):
        """
        Sanitize the ciphertext to prevent malicious senders.
        """

        if debug:
            print('\nSanitize algorithm:\n')

        # re-evaluate the policy to get matrix dimensions
        mono_span_prog = self.util.convert_policy_to_msp(ctxt['policy'])
        num_cols = self.util.len_longest_row

        # pick sanitization randomness (t0 -> our t1, t1 -> our t2)
        t0 = self.group.random(ZR)
        t1 = self.group.random(ZR)
        
        # pick random sanitization shares (vector x)
        x_vec = [t0]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            x_vec.append(rand)
            
        bHash = self.group.hash(str(self.group.order()+1), G1) # ZR+1

        ct_prime = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            
            # compute M_i * x
            Mivtop_x = sum(i[0] * i[1] for i in zip(row, x_vec[:len_row]))
            
            # ct_3,i' = ct_3,i * H(vartheta)^(M_i * x) * H(pi(i))^t1
            ct_prime[attr] = ctxt['ct'][attr] * (bHash ** Mivtop_x) * (attrHash ** t1)
            
        # update the rest components
        g_s0_prime = ctxt['g_s0'] * (pk['h'] ** t0)
        h_s1_prime = ctxt['h_s1'] * (pk['h'] ** t1)
        Cp_prime = ctxt['Cp'] * (pk['e_gh_alpha'] ** t0)

        return {'policy': ctxt['policy'], 'g_s0': g_s0_prime, 'h_s1': h_s1_prime, 'ct': ct_prime, 'Cp': Cp_prime}

    def decrypt_out(self, pk, tk, ctxt_prime): 
        """
        Cloud server partially decrypts the sanitized ciphertext.
        """
        if debug:
            print('\nDecrypt_out algorithm:\n')

        nodes = self.util.prune(ctxt_prime['policy'], tk['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return 0

        prod_tk = 1
        prod_ct = 1
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)

            prod_tk *= tk['sk1'][attr_stripped]
            prod_ct *= ctxt_prime['ct'][attr]
        
        # execute pairing operations
        e0 = pair(tk['sk2'], ctxt_prime['g_s0'])
        e1 = pair(prod_tk, ctxt_prime['h_s1'])
        e2 = pair(prod_ct, tk['h_r'])

        kem = e0 * (e1/e2)
        
        return {'Cp_prime': ctxt_prime['Cp'], 'kem': kem}

    def decrypt_user(self, pk, dk, partial_ctxt): 
        """
        User fully decrypts using the lightweight decryption key dk.
        """
        if debug:
            print('\nDecrypt_user algorithm:\n')

        if partial_ctxt == 0:
            return 0

        # compute PC^(1/z)
        z_inv = 1 / dk
        recovered_kem = partial_ctxt['kem'] ** z_inv
        
        return partial_ctxt['Cp_prime'] / recovered_kem