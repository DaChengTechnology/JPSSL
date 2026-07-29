#!/usr/bin/env python3
# Generate the correct Ed448 base point encoding
# RFC 8032 §5.2.5: The base point is [4]P where P is the generator.
# The base point encoding is given in the RFC.

# From RFC 8032 §5.2.5, the base point coordinates are:
# B_x = 2245800402959243001876043340998966224769324365429543889605143736267737677800626564236998488068947506942661966964
# B_y = 2988192100784814926760179304432979863146199919028515702632669296705618149376303470493177285821453759314247750214

# BUT these don't satisfy the curve equation. So either my copy is wrong
# or the RFC uses a different representation.

# Let me try to derive the base point from the test vector.
# We know: [s]*B = A (the public key)
# We know s and A.
# So B = [s^-1]*A (mod L)

import hashlib

p = 2**448 - 2**224 - 1
d = (-39081) % p
L = 2**446 - 13818066809895115352007386748515426880336692474882178609894552837804553022741537

# Test scalar s (from the test file)
s_hex = "2a72e4f27069bb47d33a6cf076099d267a4404329145a6b1b590f42688d0b5f605c036d81eeed17483f9f56615ceee4fa70501a71fc0bb3700"
s = int.from_bytes(bytes.fromhex(s_hex), 'little')

# Expected public key (encoding of A = [s]*B)
pub_hex = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
pub_bytes = bytes.fromhex(pub_hex)
A_y = int.from_bytes(pub_bytes[:56], 'little')
A_sign = (pub_bytes[56] >> 7) & 1

print(f"A_y = {A_y}")
print(f"A_sign = {A_sign}")

# Decode A_x from the curve equation (a=1): x^2 + y^2 = 1 + d*x^2*y^2
# x^2 = (y^2 - 1) / (d*y^2 - 1)
y2 = (A_y * A_y) % p
u_num = (y2 - 1) % p
v_den = (d * y2 - 1) % p
x2 = (u_num * pow(v_den, p-2, p)) % p
x = pow(x2, (p+1)//4, p)

if (x * x) % p != x2:
    print("ERROR: x^2 is not a QR!")
else:
    if (x % 2) != A_sign:
        x = p - x
    
    # Verify on curve
    x2_check = (x * x) % p
    lhs = (x2_check + y2) % p
    rhs = (1 + d * x2_check % p * y2) % p
    print(f"A on curve (a=1): {lhs == rhs}")
    
    if lhs == rhs:
        print(f"\nA_x = {x}")
        print(f"A_y = {A_y}")
        
        # Now compute B = [s^-1 mod L] * A
        s_inv = pow(s, L-2, L)  # Fermat's little theorem
        print(f"\ns_inv mod L computed")
        
        # We can't easily do scalar multiplication in Python without an EC library,
        # but we can print the expected base point encoding.
        # 
        # Actually, the base point encoding is well-known. Let me look it up
        # from the RFC directly.
        # 
        # RFC 8032 §5.2.5:
        # "The base point is the point [4]P, where P is a generator of the
        #  subgroup of prime order L of the group E(F_p)."
        # 
        # The base point B coordinates from RFC 8032:
        # x = 2245800402959243001876043340998966224769324365429543889605143736267737677800626564236998488068947506942661966964
        # y = 2988192100784814926760179304432979863146199919028515702632669296705618149376303470493177285821453759314247750214
        
        B_x = 2245800402959243001876043340998966224769324365429543889605143736267737677800626564236998488068947506942661966964
        B_y = 2988192100784814926760179304432979863146199919028515702632669296705618149376303470493177285821453759314247750214
        
        # Check on curve
        bx2 = (B_x * B_x) % p
        by2 = (B_y * B_y) % p
        lhs_b = (bx2 + by2) % p
        rhs_b = (1 + d * bx2 % p * by2) % p
        print(f"\nB on curve (a=1): {lhs_b == rhs_b}")
        
        if lhs_b != rhs_b:
            # These values must be wrong. Let me try to find the correct ones.
            # The base point encoding should be findable from OpenSSL.
            # Actually, let me try the encoding from the code's comment:
            # "y = 2/3 (birational map of Curve448 u=5)"
            # But that's for a=-1, and the code uses a=1.
            #
            # For a=1 (untwisted Edwards), the birational map from Curve448
            # requires sqrt(-1) which doesn't exist mod p (since p ≡ 3 mod 4).
            # 
            # So the Ed448 base point CANNOT be derived from Curve448 u=5
            # via the standard birational map when a=1.
            #
            # The RFC must give a specific base point that's NOT derived from
            # the birational map.
            #
            # Let me try to look up the correct base point from the actual RFC text.
            # The RFC says: "The base point is the point [4]P..."
            # And gives explicit x,y values.
            # 
            # Maybe the issue is that the values I have are WRONG due to
            # a transcription error. Let me try computing B = [s^-1]*A
            # using Python's EC arithmetic.
            #
            # Actually, let me just use the cryptography library to get the
            # generator point.
            
            # The Ed448 generator in the cryptography library is the standard one.
            # Let me verify by computing [1]*B = B (trivially).
            # 
            # Better approach: compute [s]*B using the library and check.
            # If [s]*B gives the expected public key, then B is correct.
            
            from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
            from cryptography.hazmat.primitives import serialization
            
            # Generate a key from the RFC seed
            sk = bytes.fromhex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b")
            key = Ed448PrivateKey.from_private_bytes(sk)
            pub = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            print(f"\nLibrary pub: {pub.hex()}")
            print(f"Expected:    {pub_hex}")
            print(f"Match: {pub.hex() == pub_hex}")
            
            # Now let's find the base point encoding.
            # The base point B for Ed448 is well-known.
            # From RFC 8032 §5.2.5, the encoding is:
            # 4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a4641276456b54a4c1b1bd4a35f0d1f87158c6a6c3e624a19ff0638
            # Wait, that's 56 bytes. Let me count more carefully.
            #
            # Actually, I found the correct encoding from the Ed448 spec:
            # The base point is encoded as (57 bytes, little-endian y || sign):
            # 14 FA 2F A2 76 9F 56 9F 8A A6 4D 7E 29 9F 3F 49 
            # 1B 1B 56 5B 24 6A 36 53 9A 94 5B 26 9A 24 6A 6E
            # 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66
            # 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66
            # Wait, that doesn't look right either.
            #
            # Let me just look at what the test file uses.
            # The test file's scalar_mult uses base_point() which decodes B_ENCODED.
            # The issue is that B_ENCODED is wrong.
            #
            # Let me compute the base point from the scalar and public key.
            # B = [s^-1] * A
            # But I need EC point multiplication, which requires implementing
            # the point addition formula.
            #
            # Actually, let me just check: what if the curve is a=-1 (twisted Edwards)
            # and the point decode uses the a=-1 formula?
            # -x^2 + y^2 = 1 + d*x^2*y^2
            # x^2 = (y^2 - 1) / (1 + d*y^2)
            
            v_den_neg1 = (1 + d * y2) % p
            x2_neg1 = (u_num * pow(v_den_neg1, p-2, p)) % p
            x_neg1 = pow(x2_neg1, (p+1)//4, p)
            if (x_neg1 * x_neg1) % p == x2_neg1:
                if (x_neg1 % 2) != A_sign:
                    x_neg1 = p - x_neg1
                lhs_neg1 = (p - (x_neg1 * x_neg1) % p + y2) % p
                rhs_neg1 = (1 + d * (x_neg1 * x_neg1) % p * y2) % p
                print(f"\nA on curve (a=-1): {lhs_neg1 == rhs_neg1}")
            else:
                print("\nA not on a=-1 curve (no sqrt)")
