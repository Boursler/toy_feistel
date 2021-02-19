#include <iostream>
#include <iomanip>
#include <cmath>
#include <utility>
#include <cstdint>
using namespace std;
typedef struct enc_block {
        union {
                uint64_t u64;
                uint16_t u16[4];
        };
} enc_block;

uint8_t ftable[20][12];
typedef struct enc_key {
        union {
                struct {
                        uint64_t lower;
                        uint16_t upper;
                };
                uint8_t u8[10];
        };

        enc_block operator^(enc_block block)
        {
                enc_block ret = block;
                ret.u64 = ret.u64 ^ this->lower;
                return ret;
        }

        struct enc_key operator<<(int shift)
        {
                uint64_t new_lower;
                uint16_t new_upper;
                uint64_t lower = this->lower;
                uint16_t upper = this->upper;

                uint64_t rot_upper = upper >> (16 - shift);
                uint64_t rot_lower = lower >> (64 - shift);

                new_lower = (lower << shift) | rot_upper;
                new_upper = upper << shift | rot_lower;

                enc_key ret;
                ret.lower = new_lower;
                ret.upper = new_upper;
                return ret;
        }
        friend ostream &operator<<(ostream &out, const enc_key key)
        {
                for (int i = 9; i >= 0; i--) {
                        out << std::setfill('0') << std::setw(2) << std::hex
                            << (int)key.u8[i];
                }
                return out;
        }

} enc_key;

enc_key key;
unsigned int mod_val = 2 ^ 16;
int main(int argc, char **argv);
pair<unsigned short, unsigned short> F(unsigned short r_0, unsigned short r_1,
                                       unsigned short round);
unsigned long G(unsigned short w, unsigned short round);
struct whiten *whitened(uint64_t, uint64_t);
pair<unsigned short, unsigned short> F(unsigned short r_0, unsigned short r_1,
                                       unsigned short round)
{
        pair<unsigned short, unsigned short> p;
        //12 keys lookup from ftable
        /*  unsigned short t_0 = G(r_0, ftable[key], round);
  unsigned short t_1 = G(r_1, ftable[key], round);
  unsigned short f_0 = (t_0 + 2*t_1 + ftable[key]) % mod_val;
  unsigned short f_1 = (2*t_0+ t_1 + ftable[key]) % mod_val; */
        return p;
}

uint8_t K(uint8_t x)
{
        key = key << 0x1;
        cout << key << endl;
        uint8_t index = x % 10;
        return key.u8[index];
}
enc_block whitened(enc_block block, enc_key key)
{
        // enc_block out;
        // for (uint16_t i = 0; i < 4; i++) {
        //         out.u16[i] = input_block.u16[i] ^ key.u16[i];
        // }
        // return out;
        return key ^ block;
}

void generate_table()
{
        for (uint8_t round = 0; round < 20; round++) {
                for (uint8_t i = 0; i < 12; i++) {
                        ftable[round][i] = K(4 * round + i % 4);
                }
        }
}
int main(int argc, char **argv)
{
        enc_key test;
        test.lower, key.lower = 0xef0123456789abcd;
        test.upper, key.upper = 0xabcd;
        enc_key res = test << 0x1;
        res = res << 0x1;
        res = res << 0x1;
        res = res << 0x1;
        cout << "Test result  \n";
        cout << test << endl;
        cout << res << endl;
        generate_table();
        for (uint8_t round = 0; round < 20; round++) {
                for (uint8_t i = 0; i < 12; i++) {
                        cout << std::hex << (int)ftable[round][i] << " ";
                }
                cout << "\n";
        }
}
