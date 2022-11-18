# collaborative-zksnark

## Test for Poseidon Hash with 2 clients using groth16

$cd mpc-snarks

$./target/debug/client --hosts data/2 groth16 --party 0&

$./target/debug/client --hosts data/2 groth16 --party 1&
