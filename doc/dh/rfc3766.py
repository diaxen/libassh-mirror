
import math

# section 2.2: L(n) = 0.02 * e^ (1.92 * cubrt(ln(n) * ( ln( ln(n)))^2))
def L(n):
    return 0.02 * pow(2.71828182846, 1.92 *
            pow(math.log(n) * (math.log(math.log(n)))**2, 1/3))

# check examples given in section 4
assert abs(math.log(L(2**1195), 2) - math.log(3*10**13 * 5*10**12, 2)) < 1
assert abs(math.log(L(2**2077), 2) - math.log(2**112, 2)) < 1
assert abs(math.log(L(2**2439), 2) - math.log(300 * 2**112, 2)) < 1

# plot
yl = -10
for x in range(10, 20000):
    y = math.log(L(2**x), 2)
    if (y - yl > 5):
        print (y, x)
        yl = y;

