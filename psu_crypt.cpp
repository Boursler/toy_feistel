#include <iostream>
#include <iomanip>
#include <cmath>
#include <utility>
#include <cstdint>
using namespace std;
const int MAX_VAL = 65536;
typedef struct enc_block {
        union {
                uint64_t u64;
                uint16_t u16[4];
                uint8_t u8[8];
        };
        friend ostream &operator<<(ostream &out, const enc_block in)
        {
                for (int i = 0; i < 8; i++) {
                        out << std::setfill('0') << std::setw(2) << std::hex
                            << (int)in.u8[i] << " ";
                }
                return out;
        }
} enc_block;

uint8_t subkeys[20][12];
uint8_t ftable[] = {
        0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78,
        0x99, 0xb1, 0xaf, 0xf9, 0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e,
        0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28, 0x0a, 0xdf, 0x02, 0xa0,
        0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
        0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5,
        0xf7, 0x16, 0x6a, 0xa2, 0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b,
        0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8, 0x55, 0xb9, 0xda, 0x85,
        0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
        0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56,
        0x6d, 0x98, 0x9b, 0x76, 0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20,
        0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d, 0x42, 0xed, 0x9e, 0x6e,
        0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
        0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9,
        0x5d, 0x5c, 0x31, 0xa4, 0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87,
        0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40, 0x34, 0x4b, 0x1c, 0x73,
        0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
        0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e,
        0xff, 0x8c, 0x0e, 0xe2, 0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1,
        0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8, 0x08, 0x77, 0x11, 0xbe,
        0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
        0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01,
        0x05, 0x59, 0x2a, 0x46
};
typedef struct enc_key {
        union {
                struct {
                        uint64_t lower;
                        uint16_t upper;
                };
                uint8_t u8[10];
                uint16_t u16[5];
        };

        enc_block operator^(enc_block block)
        {
                enc_block ret = block;
                for (int i = 0; i < 8; i++) {
                        ret.u8[i] ^= this->u8[9 - i];
                }
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
                for (int i = 0; i < 10; i++) {
                        out << std::setfill('0') << std::setw(2) << std::hex
                            << (int)key.u8[i];
                }
                return out;
        }

} enc_key;

typedef struct f_round {
        union {
                struct {
                        uint16_t lower;
                        uint16_t upper;
                };
                uint32_t u32;
                uint8_t u8[4];
        };
        friend ostream &operator<<(ostream &out, const f_round in)
        {
                out << std::setfill('0') << std::setw(4) << std::hex
                    << (int)in.lower << " " << (int)in.upper;
                return out;
        }
} f_round;
typedef struct g_word {
        union {
                struct {
                        uint8_t lower;
                        uint8_t upper;
                };
                uint16_t u16;
        };
        friend ostream &operator<<(ostream &out, const g_word in)
        {
                out << std::setfill('0') << std::setw(2) << std::hex
                    << (int)in.lower << " " << (int)in.upper;
                return out;
        }
} g_word;

enc_key key = { .u8 = { 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd,
                        0xab } };

int main(int argc, char **argv);
f_round F(uint16_t r_0, uint16_t r_1, uint16_t round_num);
uint16_t G(uint16_t w, uint8_t k_0, uint8_t k_1, uint8_t k_2, uint8_t k_3);
enc_block whiten(enc_block, enc_key);
f_round F(uint16_t r_0, uint16_t r_1, int round_num)
{
        f_round ret;
        //12 keys lookup from ftable
        //k0,k1,k2,k3
        uint16_t t_0 = G(r_0, subkeys[round_num][0], subkeys[round_num][1],
                         subkeys[round_num][2], subkeys[round_num][3]);
        //k4,k5,k6,7
        uint16_t t_1 = G(r_1, subkeys[round_num][4], subkeys[round_num][5],
                         subkeys[round_num][6], subkeys[round_num][7]);
        ret.lower = (t_0 + 2 * t_1 +
                     (subkeys[round_num][8] << 8 | subkeys[round_num][9])) %
                    MAX_VAL;
        ret.upper = (2 * t_0 + t_1 +
                     (subkeys[round_num][10] << 8 | subkeys[round_num][11])) %
                    MAX_VAL;
        cout << "t0: " << std::hex << setw(4) << setfill('0') << t_0
             << " t1: " << t_1 << endl;

        cout << "f0: " << std::hex << setw(4) << setfill('0') << ret.lower
             << " f1: " << ret.upper << endl;

        return ret;
}

uint16_t G(uint16_t w, uint8_t k_0, uint8_t k_1, uint8_t k_2, uint8_t k_3)
{
        g_word parse_wd;
        parse_wd.u16 = w;
        uint8_t g_1 = parse_wd.lower;
        uint8_t g_2 = parse_wd.upper;
        uint8_t g_3 = ftable[g_2 ^ k_0] ^ g_1;
        uint8_t g_4 = ftable[g_3 ^ k_1] ^ g_2;
        uint8_t g_5 = ftable[g_4 ^ k_2] ^ g_3;
        uint8_t g_6 = ftable[g_5 ^ k_3] ^ g_4;
        g_word ret;
        cout << "g1: " << std::hex << setw(2) << setfill('0') << (int)g_1;
        cout << " g2: " << std::hex << setw(2) << setfill('0') << (int)g_2;
        cout << " g3: " << std::hex << setw(2) << setfill('0') << (int)g_3;
        cout << " g4: " << std::hex << setw(2) << setfill('0') << (int)g_4;
        cout << " g5: " << std::hex << setw(2) << setfill('0') << (int)g_5;
        cout << " g6: " << std::hex << setw(2) << setfill('0') << (int)g_6;
        cout << endl;

        ret.lower = g_6;
        ret.upper = g_5;
        return ret.u16;
}
uint8_t K(uint8_t x)
{
        key = key << 0x1;
        uint8_t index = x % 10;
        return key.u8[index];
}
enc_block whiten(enc_block block, enc_key key)
{
        return key ^ block;
}

void generate_table()
{
        for (uint8_t round = 0; round < 20; round++) {
                for (uint8_t i = 0; i < 12; i++) {
                        subkeys[round][i] = K(4 * round + i % 4);
                }
        }
}

enc_block round(enc_block block, int round_num)
{
        if (round_num > 0)
                cout << "\n";
        cout << "Round " << std::dec << round_num << endl;
        cout << "Keys:";
        for (int i = 0; i < 12; i++) {
                cout << " " << std::hex << std::setw(2) << std::setfill('0')
                     << (int)subkeys[round_num][i];
        }
        cout << endl;

        f_round fr;
        fr = F(block.u16[0], block.u16[1], round_num);

        uint16_t r0, r1, r2, r3;
        r0 = block.u16[0];
        r1 = block.u16[1];
        r2 = block.u16[2];
        r3 = block.u16[3];
        block.u16[0] = r2 ^ (fr.u8[1] | (fr.u8[0] << 8));
        block.u16[1] = r3 ^ (fr.u8[3] | (fr.u8[2] << 8));
        block.u16[2] = r0;
        block.u16[3] = r1;
        cout << "Block: " << block << endl;
        return block;
}
enc_block finalize(enc_block block)
{
        enc_block cipher;
        cipher.u16[0] = block.u16[2];
        cipher.u16[1] = block.u16[3];
        cipher.u16[2] = block.u16[0];
        cipher.u16[3] = block.u16[1];
        cipher = whiten(cipher, key);
        cout << "Ciphertext: " << cipher << endl;
        return cipher;
}
enc_block encrypt_block(enc_block block)
{
        block = whiten(block, key);
        cout << "Whiten block: " << block << endl;
        for (int round_num = 0; round_num < 20; round_num++) {
                block = round(block, round_num);
        }
        return finalize(block);
}

enc_block decrypt_block(enc_block block)
{
  block = whiten(block, key);
  cout << "Whiten block: " << block << endl;
  for (int round_num = 19; round_num >= 0; round_num--) {
    block = round(block, round_num);
  }
  return finalize(block);
}
int main(int argc, char **argv)
{
        enc_block text = { .u8 = { 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74,
                                   0x79 } };
        generate_table();
        enc_block ciphertext = encrypt_block(text);
        enc_block plaintext = decrypt_block(ciphertext);
        if(text.u64 == plaintext.u64){
          cout << "Successfully encrypted and decrypted block" << endl;
          return 0;
        } else {
          cout << "Catastrophic failure of previously unimagined proportions" << endl;
          return -1;
        }
}
