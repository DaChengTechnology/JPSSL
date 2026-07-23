#!/usr/bin/env python3
"""Figure out correct Bx: test RFC Bx vs our derived Bx on various curve equations"""
p = 2**255 - 19
By = 4 * pow(5, -1, p) % p

# Our derived Bx (from twisted Edwards with d negative)
d_neg = (-121665 * pow(121666, -1, p)) % p
our_Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202

# RFC Bx
rfc_Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636

print("=== Test RFC Bx on various equations ===")
Bx2 = pow(rfc_Bx, 2, p)
By2 = pow(By, 2, p)

# 1. Twisted Edwards: -x^2 + y^2 = 1 + d*x^2*y^2
lhs1 = (-Bx2 + By2) % p
rhs1 = (1 + d_neg * Bx2 % p * By2) % p
print(f"1. Twisted (a=-1): -x^2+y^2 = 1+d*x^2*y^2")
print(f"   LHS={lhs1}, RHS={rhs1}, match={lhs1==rhs1}")

# 2. Untwisted Edwards: x^2 + y^2 = 1 + d*x^2*y^2
lhs2 = (Bx2 + By2) % p
rhs2 = (1 + d_neg * Bx2 % p * By2) % p
print(f"2. Untwisted (a=+1): x^2+y^2 = 1+d*x^2*y^2")
print(f"   LHS={lhs2}, RHS={rhs2}, match={lhs2==rhs2}")

# 3. Try with d positive
d_pos = (121665 * pow(121666, -1, p)) % p
lhs3 = (-Bx2 + By2) % p
rhs3 = (1 + d_pos * Bx2 % p * By2) % p
print(f"3. Twisted (a=-1), d positive: -x^2+y^2 = 1+d*x^2*y^2")
print(f"   LHS={lhs3}, RHS={rhs3}, match={lhs3==rhs3}")

lhs4 = (Bx2 + By2) % p
rhs4 = (1 + d_pos * Bx2 % p * By2) % p
print(f"4. Untwisted (a=+1), d positive: x^2+y^2 = 1+d*x^2*y^2")
print(f"   LHS={lhs4}, RHS={rhs4}, match={lhs4==rhs4}")

# 5. Try with d negative in denom
lhs5 = (-Bx2 + By2) % p
rhs5 = (1 - d_neg * Bx2 % p * By2) % p
print(f"5. -x^2+y^2 = 1 - d*x^2*y^2")
print(f"   LHS={lhs5}, RHS={rhs5}, match={lhs5==rhs5}")

# Also test our Bx
print("\n=== Test OUR derived Bx ===")
Bx2o = pow(our_Bx, 2, p)
lhs_o = (-Bx2o + By2) % p
rhs_o = (1 + d_neg * Bx2o % p * By2) % p
print(f"Twisted (a=-1): LHS={lhs_o}, RHS={rhs_o}, match={lhs_o==rhs_o}")

# Check: does RFC Bx satisfy x^2 = (1 - y^2)/(1 - d*y^2)?
# This is for x^2+y^2=1+d*x^2*y^2
num = (1 - By2) % p
den = (1 - d_neg * By2) % p
x2_unt = num * pow(den, -1, p) % p
print(f"\nUntwisted x^2 from (1-y^2)/(1-d*y^2) = {x2_unt}")
print(f"RFC Bx^2 = {Bx2}")
print(f"Match: {Bx2 == x2_unt}")

# For twisted with d positive:
num2 = (By2 - 1) % p
den2 = (1 - d_pos * By2) % p  # Note: -x^2+y^2 = 1-d_pos*x^2*y^2 => x^2 = (y^2-1)/(d_pos*y^2+1)? No...
# Let me derive: -x^2+y^2 = 1 + d*x^2*y^2 => y^2 - 1 = x^2 + d*x^2*y^2 = x^2*(1+d*y^2)
# If d is positive: x^2 = (y^2-1)/(1+d_pos*y^2)
x2_pos = (By2 - 1) * pow(1 + d_pos * By2, -1, p) % p
print(f"\nTwisted with d positive x^2 = (y^2-1)/(1+d_pos*y^2) = {x2_pos}")
print(f"RFC Bx^2 = {Bx2}")
print(f"Match: {Bx2 == x2_pos}")

# For untwisted with d positive: x^2 = (1-y^2)/(1-d_pos*y^2)
x2_unt_pos = (1 - By2) * pow(1 - d_pos * By2, -1, p) % p
print(f"\nUntwisted d positive x^2 = (1-y^2)/(1-d_pos*y^2) = {x2_unt_pos}")
print(f"RFC Bx^2 = {Bx2}")
print(f"Match: {Bx2 == x2_unt_pos}")

# Montgomery form: B*v^2 = u^3 + A*u^2 + u
# Map from Montgomery to Edwards: 
# In RFC 7748: u = 9 (basepoint), A = 486662
# For birational map to Edwards:
# x = u/v * sqrt(-A-2) / sqrt(-A)  ... need to check exact formula
# Actually the birational map from Curve25519 to Ed25519 is:
# If (u,v) is on B*v^2 = u^3 + A*u^2 + u, then
# x = sqrt(-A-2) * u / v  and  y = (u-1)/(u+1)
# where d = -A/(A+2) * (A+2-...)/something
# More precisely from RFC 8032:
# u = (1+y)/(1-y)  and  v = sqrt(-A-2)*u/x
# So in reverse: from Edwards (x,y) to Montgomery:
# u = (1+y)/(1-y)
# v = sqrt(-A-2)*u/x = ... 
# This is getting complex. Let me just check if there's a direct mapping.
