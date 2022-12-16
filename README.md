# collaborative-zksnark

## Test for Poseidon Hash with 2 clients using groth16

$cd mpc-snarks

$./target/debug/client --hosts data/2 groth16 --party 0&

$./target/debug/client --hosts data/2 groth16 --party 1&

$./target/debug/proof -p groth16 -c squaring --computation-size 10 mpc --hosts ./data/2 --party 0 --alg spdz &

$./target/debug/proof -p groth16 -c squaring --computation-size 10 mpc --hosts ./data/2 --party 1 --alg spdz &
