#!/usr/bin/env zsh

pkill proof || true

partyid=0

for c in {15..24}
do
    echo "Running snark delegator with 2^$c constraints"
    constraints=$(echo "2^$c" | bc)
    for i in {0..4}
    do
        trace="results/marlin-snark-$c-$i.txt"
        ./target/release/proof -p marlin -c squaring --computation-size $constraints mpc --hosts ./data/hosts --party $partyid --alg spdz > $trace 2>&1
    done
done
