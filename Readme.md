# minimal example of noise growth with HEXL

## Build
```
git submodule update --init
mkdir SEAL/build
cd SEAL/build
cmake .. -DSEAL_USE_INTEL_HEXL=ON
make -j
cd ../..
mkdir build
cd build
cmake ..
make run
# then compare with SEAL_USE_INTEL_HEXL=OFF
```