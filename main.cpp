#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <seal/seal.h>

using namespace seal;

namespace PARAMS {
constexpr uint64_t PLAIN_MODULUS = (4398046150657ULL); // 42 bit
constexpr uint64_t MAX_PRIME_SIZE = ((1ULL << 42) - 1);
constexpr uint64_t MOD_DEGREE = 16384;
} // namespace PARAMS

int main() {
  EncryptionParameters parms(scheme_type::bfv);
  parms.set_poly_modulus_degree(PARAMS::MOD_DEGREE);
  sec_level_type sec = sec_level_type::tc128;
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(PARAMS::MOD_DEGREE));
  parms.set_plain_modulus(PARAMS::PLAIN_MODULUS);

  SEALContext context(parms, true, sec);
  KeyGenerator kg(context);
  SecretKey sk = kg.secret_key();
  GaloisKeys galois_keys;
  kg.create_galois_keys(galois_keys);
  RelinKeys relin_keys;
  kg.create_relin_keys(relin_keys);

  BatchEncoder bt(context);
  Encryptor encryptor(context, sk);
  Decryptor decryptor(context, sk);
  Evaluator evaluator(context);
  //----------------------------------------------------------------

  std::cout << "Encrypting plaintext\n" << std::flush;
  std::vector<uint64_t> input(1024, 1);
  Plaintext pt;
  bt.encode(input, pt);
  Ciphertext ciph;
  encryptor.encrypt_symmetric(pt, ciph);
  std::cout << "...done" << std::endl;

  std::cout << "Initial noise: " << decryptor.invariant_noise_budget(ciph)
            << std::endl;

  //----------------------------------------------------------------

  std::chrono::high_resolution_clock::time_point time_start, time_end;
  std::chrono::milliseconds time_diff;
  size_t slots = bt.slot_count();

  std::cout << "Computing mask..." << std::flush;
  Ciphertext output;
  time_start = std::chrono::high_resolution_clock::now();
  evaluator.multiply(ciph, ciph, output);
  time_end = std::chrono::high_resolution_clock::now();
  time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(time_end -
                                                                    time_start);
  std::cout << "...done" << std::endl;
  std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

  //----------------------------------------------------------------

  std::cout << "Final noise: " << decryptor.invariant_noise_budget(output)
            << std::endl;
  std::cout << "Decrypting..." << std::flush;

  std::vector<uint64_t> res;
  Plaintext pt_dec;
  decryptor.decrypt(output, pt_dec);
  bt.decode(pt_dec, res);
  std::cout << "...done" << std::endl;

  return 0;
}
