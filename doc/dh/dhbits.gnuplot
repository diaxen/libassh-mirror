set xlabel "Strength (bits)"
set ylabel "Modulus size (bits)"
plot "rfc3526.plot" using 2:1 title "rfc3526 e1", "rfc3526.plot" using 3:1 title "rfc3526 e2", "rfc3766.plot" title "rfc3766" with lines, x**2/4, x**2/8, x**2/12, x**2/16
