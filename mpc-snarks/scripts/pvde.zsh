#!/usr/bin/env zsh

pkill proof || true

proof=$1
infra=$2
n_parties=$3

if [[ -z $BIN ]]
then
    BIN=./target/release/proof
fi

if [[ -z $NETWORK_CONFIG ]]
then
    NETWORK_CONFIG=./data/$n_parties
fi


case $infra in 
    hbc|spdz|gsz)
        PROCS=()
        for c in {15..15}
        do
            echo "Running snark delegator with 2^$c constraints"
            constraints=$(echo "2^$c" | bc)
            #for parityid in {0..2}
            for parityid in $(seq 0 $(($n_parties - 1)))
            do
                trace="results/pvde-snark-$c-$parityid.txt"
                #./target/release/proof -p plonk -c squaring --computation-size $constraints mpc --hosts ./data/3 --party $parityid --alg spdz &
                if [ $parityid -eq 0 ]
                then
                    $BIN -p $proof -c squaring --computation-size $constraints mpc --hosts $NETWORK_CONFIG --party $parityid --alg $infra &
                    #pid=$!
                else
                    $BIN -p $proof -c squaring --computation-size $constraints mpc --hosts $NETWORK_CONFIG --party $parityid --alg $infra > /dev/null &
                fi
            done
        done
    ;;
    local)
        for c in {8..8}
        do
            constraints=$(echo "2^$c" | bc)
            $BIN -p $proof -c squaring --computation-size $constraints local
        done
    ;;
    *)
    ;;
esac

trap - INT TERM EXIT