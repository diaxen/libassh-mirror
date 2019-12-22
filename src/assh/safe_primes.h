/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013-2020 Alexandre Becoulet <alexandre.becoulet@free.fr>

  This library is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301 USA

*/


#ifndef ASSH_SAFEPRIME_H_
#define ASSH_SAFEPRIME_H_

#include "assh.h"

/** @internal
    The output of @ref assh_safeprime_lfsr with the most significant bit
    forced to 1, interpreted as a big number stored least significant
    byte first, serve as base value to forge a safe prime. A value from
    the assh_safeprime_offset array must be added to the base value in
    order to obtain a safe prime number. The array contains offsets for
    number bit sizes multiple of 8 between 1024 and 16384 bits.

    The lfsr polynomial and base seed used to generate the base values
    are shared by at most 1024 numbers. This allows updating only a
    subset of the safe prime numbers. The seed used to generate a specific
    base value is obtained by xoring the base seed and the number bit
    size. */
struct assh_safeprimes_s
{
  uint32_t poly[4];
  uint32_t seed[4];
  uint32_t offset[1921];
};


/** @internal @see assh_safeprimes_s */
ASSH_INLINE void
assh_safeprime_lfsr(uint8_t *data, size_t len, uint32_t poly, uint32_t seed)
{
  while (len--)
    {
      seed = (~((seed & 1) - 1) & poly) ^ (seed >> 1);
      *data++ = seed ^ (seed >> 8) ^ (seed >> 16) ^ (seed >> 24);
    }
}

/** @internal @This generates a base value and offset suitable to generate
    a safe prime number of the requested bit size. @see assh_safeprimes_s */
ASSH_INLINE void
assh_safeprime_get(const struct assh_safeprimes_s *desc, size_t bits,
		   uint8_t *bignum, intptr_t *offset)
{
    assert(bits % 8 == 0 && bits >= 1024 && bits <= 16384);
    uint32_t poly = desc->poly[(bits - 1024) / 4096];
    uint32_t seed = desc->seed[(bits - 1024) / 4096];
    assh_safeprime_lfsr(bignum, bits / 8, poly, seed ^ bits);
    bignum[bits / 8 - 1] |= 0x80;
    *offset = desc->offset[(bits - 1024) / 8];
}

static const struct assh_safeprimes_s assh_safeprimes = {
 .poly = { 0x8a523d7c, 0x8a523d7c, 0x8a523d7c, 0x8a523d7c },
 .seed = { 0x12345678, 0x12345678, 0x12345678, 0x12345678 },
 .offset = {
    /* 1024 bits */
    0x000ae769, 0x001e0fb9, 0x0003b145, 0x00039845, 0x00049419, 0x000408ad, 0x00193095, 0x000542f5,
    0x0039ae6d, 0x000151a9, 0x0002e261, 0x000eda0d, 0x00042639, 0x0020dffd, 0x00055779, 0x00221641,
    0x0015e189, 0x00037a95, 0x00018519, 0x0002a36d, 0x002766b9, 0x001ef3d1, 0x0004c5fd, 0x000d507d,
    0x00043311, 0x009142e1, 0x000d19a9, 0x00061fd5, 0x000f3fb5, 0x001a0515, 0x0000c921, 0x00023851,
    0x004fe91d, 0x0001708d, 0x00118609, 0x0049dd7d, 0x0002ac75, 0x000b51c9, 0x0024cc69, 0x0015e57d,
    0x0003e94d, 0x000f6025, 0x0047a911, 0x000c5415, 0x0017f525, 0x00034d0d, 0x00341f85, 0x00138481,
    0x00149db1, 0x000af52d, 0x000bf4fd, 0x000c4ef1, 0x00040819, 0x0014c5dd, 0x0002d831, 0x0013f10d,
    0x000e80c9, 0x0004601d, 0x0059de31, 0x0028c2e9, 0x00084399, 0x0008105d, 0x009ca0fd, 0x000d8f09,
    0x00075684, 0x001287e8, 0x00118e78, 0x0038e774, 0x0027e9fc, 0x0022c380, 0x001681ec, 0x001858ec,
    0x001a3fb4, 0x0052c380, 0x00045070, 0x0012875c, 0x0013c238, 0x00132a08, 0x000ea4c0, 0x001d9ea4,
    0x007380c4, 0x0029a148, 0x00081134, 0x00136d24, 0x0001cbe8, 0x002a1104, 0x0003bf54, 0x0048be34,
    0x003c09f8, 0x0052ae50, 0x000aa834, 0x0016152c, 0x00379738, 0x001ab308, 0x00345850, 0x003e34f4,
    0x000955bc, 0x001a39ec, 0x0010f530, 0x00546b14, 0x005c408c, 0x0010e804, 0x00369370, 0x001a07cc,
    0x00033b20, 0x0079d4c4, 0x0091799c, 0x00015bfc, 0x0012faf8, 0x0007025c, 0x001a4714, 0x005ef72c,
    0x0016a07c, 0x00036dcc, 0x002de07c, 0x0013b484, 0x008367c0, 0x000508b4, 0x0020d07c, 0x0037f9d8,
    0x00193ba4, 0x0000e444, 0x002e00d0, 0x00205634, 0x001ac6f8, 0x0008088c, 0x001f3dac, 0x000adde8,
    0x000ac433, 0x001ef857, 0x001bc0bf, 0x00251227, 0x007205a3, 0x0006d787, 0x0032df8b, 0x0010fc0f,
    0x002fd3d7, 0x0045922f, 0x00073d1f, 0x00253fb7, 0x0016e3c7, 0x002edc73, 0x0009333f, 0x000709a3,
    0x000cffdf, 0x003001f7, 0x0033258b, 0x00235a7f, 0x00be3947, 0x00406843, 0x00175c6f, 0x0002b9bf,
    0x000cccbb, 0x0077c8df, 0x0022de6b, 0x004d60c3, 0x00033f27, 0x0011a1a3, 0x00229117, 0x0009ae5f,
    0x002c4f3f, 0x008e7d87, 0x001608db, 0x00343e87, 0x00bcaf5b, 0x0013f1c7, 0x008b299b, 0x000171f7,
    0x003954c3, 0x004f4e3f, 0x0009e69b, 0x004b624b, 0x0095b5df, 0x00d82887, 0x00612677, 0x0004299f,
    0x00369e6b, 0x00319aff, 0x001a2d5f, 0x0021195f, 0x008984b3, 0x000c3943, 0x002ba2db, 0x00606307,
    0x0025c25b, 0x00373333, 0x004d9567, 0x003a7c67, 0x0053ca43, 0x0026694f, 0x004220b7, 0x00286ef7,
    0x00a5b88e, 0x00365c42, 0x0082b77e, 0x008eb26e, 0x0003a7ce, 0x00264996, 0x0088e676, 0x0001bd72,
    0x0023b946, 0x0002f396, 0x001d60aa, 0x0008f3ce, 0x001a0a12, 0x00538ad6, 0x0031500a, 0x0029009a,
    0x0075f50a, 0x0042d35a, 0x009ffa3e, 0x00283e56, 0x006978f2, 0x001095ee, 0x0000418e, 0x00bb4b32,
    0x019267f6, 0x001e2a76, 0x006813fe, 0x00275c12, 0x00b1e04e, 0x000bd70a, 0x00035376, 0x001eae52,
    0x00025a4e, 0x0016f3f2, 0x003f0612, 0x002d1e36, 0x000750ca, 0x0028f976, 0x0007eb2e, 0x00f51702,
    0x0236c39a, 0x0018b8c2, 0x0040d1e2, 0x0065f6fe, 0x0037bdb6, 0x01cc644a, 0x0029586e, 0x0067a2f6,
    0x003f3176, 0x01a6c29e, 0x002367d6, 0x0000faca, 0x000f4a46, 0x00dbf062, 0x005c1baa, 0x007bbcfa,
    0x00a7d22e, 0x003f1b1e, 0x00048ba6, 0x00426ffa, 0x0049eb6e, 0x003f3852, 0x000036b2, 0x00918b32,
    0x001b1e61, 0x00a7c0b9, 0x01651b35, 0x003988e9, 0x00222e61, 0x00c7e435, 0x007f2e89, 0x0054c351,
    0x001b4069, 0x001de6d1, 0x00d9e5cd, 0x000f6d89, 0x01260275, 0x01683565, 0x0065761d, 0x001ba199,
    0x000b1d41, 0x000cb609, 0x0021df21, 0x0008e8fd, 0x00563d0d, 0x0018e791, 0x005508f5, 0x0092ee35,
    0x00612395, 0x0028c6d9, 0x00a11fad, 0x0024daa1, 0x00025dd5, 0x00006681, 0x00f8fa09, 0x0000d1c9,
    0x013f02a1, 0x003eb2dd, 0x0069e9ad, 0x003f8441, 0x000c86f1, 0x00aef3f1, 0x00335945, 0x0013c611,
    0x00f6b079, 0x000202e9, 0x016a0cd9, 0x001c9009, 0x00a9ade5, 0x0282640d, 0x0063c41d, 0x0032ae0d,
    0x003fbc5d, 0x007b96a1, 0x00852d3d, 0x0050fa41, 0x000972c1, 0x001ce669, 0x000f914d, 0x008a58bd,
    0x012bec39, 0x01dffbb5, 0x00be0895, 0x00ed3bbd, 0x01d0ad7d, 0x005b2199, 0x00f5cf2d, 0x0011fa51,
    0x0014ecec, 0x01639098, 0x0039d018, 0x0037ccec, 0x003de9d4, 0x0012aab8, 0x00155e88, 0x0116ca8c,
    0x02327fdc, 0x0066a1d8, 0x0030da1c, 0x002839cc, 0x00bbbbd8, 0x029cea54, 0x01310e48, 0x011bdc18,
    0x017147c8, 0x007657a8, 0x008b1e78, 0x00553454, 0x0108bca4, 0x00650620, 0x00c8c5e4, 0x002704a4,
    0x02354024, 0x00a58ef0, 0x0073d3d8, 0x0024cbf0, 0x01466798, 0x01094b68, 0x00bccc60, 0x0001a830,
    0x01287070, 0x00839ae8, 0x0055d738, 0x0017b3f0, 0x00e51628, 0x00ea0ff8, 0x029dd484, 0x00be09d8,
    0x00ac3928, 0x0043f9b4, 0x005d4278, 0x00123750, 0x00a13438, 0x01643bb4, 0x01a9a430, 0x00ac5944,
    0x004a53e8, 0x00226a30, 0x015cc7d8, 0x001a4080, 0x009310fc, 0x00160450, 0x021edd74, 0x000893f0,
    0x001a86e0, 0x00bf9bd8, 0x008e7934, 0x00731fdc, 0x03ab9c48, 0x00c49fb0, 0x0060ad94, 0x005cb318,
    0x004000e3, 0x002eaf83, 0x00e000cb, 0x0029a0e3, 0x01479bdb, 0x001de8fb, 0x01321047, 0x006811c7,
    0x00b45e97, 0x002f6dab, 0x00b0d70b, 0x02c5ded3, 0x00e1dcfb, 0x011f6adf, 0x0009c797, 0x0036c657,
    0x009d3af7, 0x0128b4f7, 0x002d6b13, 0x001463b7, 0x01434ccb, 0x00d30afb, 0x01fcfa9b, 0x0187324b,
    0x001374c7, 0x000fa463, 0x002abd17, 0x0004504b, 0x00c0ce37, 0x007cca0b, 0x0179531f, 0x0068271b,
    0x00493db7, 0x00f04c0b, 0x01a92c0b, 0x00703107, 0x00051cb7, 0x017198af, 0x00805f13, 0x00d34f1b,
    0x0058ebf3, 0x0003764f, 0x02628767, 0x01eca653, 0x0095c517, 0x0023571f, 0x003e602f, 0x0047736f,
    0x000d5c33, 0x00661383, 0x00632f3f, 0x003438c7, 0x017341e7, 0x01ddd9af, 0x03311557, 0x017a5237,
    0x00d0aa1f, 0x0124b977, 0x006b3d63, 0x00f012b7, 0x01ac5cff, 0x009e6127, 0x027f16ff, 0x006ef2af,
    0x001a1266, 0x0093aefe, 0x011a26c2, 0x006f397e, 0x009f252e, 0x0182eb5e, 0x001eef5e, 0x0057b7d6,
    0x000a3ada, 0x007ad282, 0x001b9cb6, 0x0157d40e, 0x00371022, 0x015e49aa, 0x01f8c3f2, 0x00e91e3e,
    0x007c6376, 0x012a4552, 0x029f4c7e, 0x007080da, 0x01360ba2, 0x0029e99e, 0x00179c2a, 0x00e2866a,
    0x0141113e, 0x00688a2e, 0x00018102, 0x038655e6, 0x01f0fcca, 0x02f96f96, 0x00bb0e06, 0x01f35d2e,
    0x00074462, 0x0052121a, 0x01eb7512, 0x0044078a, 0x00914ed6, 0x0045e94e, 0x00a7d66e, 0x01282426,
    0x01e1f3aa, 0x00dd6002, 0x01517eee, 0x0121cd42, 0x00371ffa, 0x007c25d2, 0x00123362, 0x00af383e,
    0x007bb32e, 0x007f7de2, 0x00980bb2, 0x0075f646, 0x002f16fe, 0x00fc3316, 0x0016f9fa, 0x01123172,
    0x0022a392, 0x01305192, 0x00f5a53e, 0x00396d52, 0x00441332, 0x00dce8f6, 0x006182ce, 0x0032932a,
    /* 5120 bits */
    0x01bbe8d1, 0x008afae1, 0x01d3488d, 0x01d0269d, 0x0063b9dd, 0x01e37b55, 0x01232f75, 0x0165a175,
    0x0062c885, 0x0176e791, 0x000099f1, 0x00bd54e9, 0x0143b0fd, 0x01937565, 0x00def401, 0x069d13fd,
    0x00ea0115, 0x03732575, 0x0071f3e5, 0x014e5cc9, 0x003d0ea5, 0x00ca06fd, 0x007836ad, 0x024116bd,
    0x019c1999, 0x0233e4e9, 0x008c1215, 0x00eeccad, 0x01303305, 0x031eaecd, 0x01e084fd, 0x02193ee1,
    0x0016bdb1, 0x03ce9db1, 0x042821a9, 0x00a3ca3d, 0x00b43929, 0x04c33e65, 0x001fd435, 0x002968ad,
    0x005700c5, 0x010a2ed5, 0x00493e29, 0x0168dd55, 0x0382b4b5, 0x00cb3245, 0x0025bdcd, 0x0206e23d,
    0x00d1e6a1, 0x01125991, 0x0330aa6d, 0x00ce907d, 0x006976b9, 0x0005d8a5, 0x00ea1281, 0x00888c61,
    0x00a50a19, 0x01a45291, 0x042e1675, 0x00439341, 0x001349a1, 0x00886609, 0x00124c6d, 0x04a78049,
    0x00b184a8, 0x00613b38, 0x017b5ecc, 0x051c9544, 0x00f797a8, 0x00b26018, 0x054c7f24, 0x003420d4,
    0x017340e8, 0x00500524, 0x00230d68, 0x008db9b4, 0x006e8064, 0x01640c04, 0x00abace4, 0x00ba9adc,
    0x0134a788, 0x007847bc, 0x01b0e384, 0x01a7e234, 0x015199c4, 0x00adc378, 0x0056de10, 0x00922a2c,
    0x00b76ff0, 0x00f3bde8, 0x01490014, 0x00f1dd90, 0x0004cdc4, 0x0108f608, 0x001ec2a0, 0x0160627c,
    0x00ba6d30, 0x003d5cc8, 0x04d05624, 0x03857418, 0x008916c0, 0x007c0048, 0x002a4c48, 0x00a92158,
    0x048a950c, 0x02064bf4, 0x02658e48, 0x00429b0c, 0x00fe9bcc, 0x03345608, 0x02211244, 0x002a17a0,
    0x01e49c64, 0x088dd314, 0x01936ba8, 0x033d56c4, 0x009ddeac, 0x0168ae00, 0x03071598, 0x00077f98,
    0x00657464, 0x03716e48, 0x003694a0, 0x046b87b0, 0x00767f44, 0x001b268c, 0x013c4514, 0x062d1d20,
    0x01636803, 0x01bea20f, 0x0004af5b, 0x001a8087, 0x01996ac3, 0x00593947, 0x00836ccb, 0x020123db,
    0x02ee83c3, 0x02903273, 0x016f9c03, 0x01b8daaf, 0x00493e53, 0x00417223, 0x03643687, 0x00bb2ad3,
    0x03497b63, 0x0531a58b, 0x02fcc14b, 0x0293df2b, 0x00d84d6b, 0x003ac2c3, 0x022ed6ef, 0x016254b7,
    0x01dc93df, 0x05ae2243, 0x006f66ff, 0x01d229cb, 0x02118263, 0x003a8b5b, 0x03d6c4e7, 0x01e1d1a7,
    0x0076555f, 0x01472527, 0x0117222b, 0x0374f3d3, 0x000c76fb, 0x022b5b77, 0x01cdb607, 0x042607af,
    0x00a32d53, 0x001b431b, 0x04e62243, 0x02803e7b, 0x04741743, 0x025c1653, 0x02083027, 0x007955ef,
    0x041c40f7, 0x02c2d727, 0x0004badf, 0x003b539b, 0x00c7823f, 0x00c7ef5f, 0x00e29253, 0x03802307,
    0x000ba81f, 0x000a699f, 0x035cff07, 0x00833ea7, 0x006e3a13, 0x0246a2ab, 0x013dc393, 0x00e8dbb3,
    0x0130bdfa, 0x009491d2, 0x03083bca, 0x0093c336, 0x00dadab2, 0x01870882, 0x06602ad2, 0x00c6f39e,
    0x031cdad2, 0x01199532, 0x0053b9ba, 0x05413032, 0x0481367a, 0x00f298ee, 0x03f6b8e6, 0x01d1e79a,
    0x0114d74a, 0x021ae5e2, 0x0043758e, 0x02ba4c26, 0x000d652e, 0x03b87c72, 0x01207cce, 0x04bec112,
    0x015a4bc6, 0x0012db42, 0x01ebe8c6, 0x0018baae, 0x0354d932, 0x026d621a, 0x064539b6, 0x014b7f1a,
    0x043e556a, 0x00fba09a, 0x02afa49a, 0x031c6762, 0x01ec8da6, 0x025d3faa, 0x043a6eee, 0x01b4f6ba,
    0x0740f2c6, 0x01644e26, 0x02bc5f46, 0x03011b92, 0x053b81fa, 0x04c0e7e2, 0x01b51572, 0x00f10e22,
    0x01399b26, 0x00a49f8e, 0x025ac532, 0x01e58022, 0x015dcbe6, 0x00a7deba, 0x036ebf1a, 0x00a1faa6,
    0x017d8eba, 0x0437f896, 0x08e7583e, 0x01d9247e, 0x001497de, 0x00c704ea, 0x009c219a, 0x0033269a,
    0x04085f1d, 0x008264f9, 0x037d54b5, 0x05ba2bad, 0x00ff5ec5, 0x0134eee5, 0x048a98e1, 0x008176c9,
    0x02f13999, 0x0155cc61, 0x00713de9, 0x0843beb9, 0x01c0b291, 0x00c978ed, 0x014ea585, 0x011b81d1,
    0x018c8fc5, 0x010c5bf9, 0x0110c3e1, 0x003b1125, 0x03049bb9, 0x0161334d, 0x047b5bb9, 0x043b4b91,
    0x00e600ad, 0x07a32e11, 0x01129229, 0x00031e29, 0x036aa6a9, 0x10147341, 0x0009d175, 0x01b950bd,
    0x02830dd9, 0x0097ff05, 0x03bc285d, 0x015c82e1, 0x030e69ed, 0x02ed72d1, 0x01019a01, 0x01ad859d,
    0x007d527d, 0x00bbe00d, 0x00c60cf5, 0x00f578f1, 0x007cebe5, 0x01a018ad, 0x02068a75, 0x0196a099,
    0x00477259, 0x04a27b69, 0x011186e9, 0x0315f301, 0x020ad2ad, 0x028c7b29, 0x05c2378d, 0x00c60301,
    0x002f51c5, 0x00bb1b35, 0x01726bf1, 0x020e347d, 0x00208d4d, 0x05017a05, 0x0620e375, 0x03dada71,
    0x03596450, 0x00b1d19c, 0x00e20830, 0x02a63950, 0x027be0f4, 0x05a91188, 0x006f38ec, 0x03b06b38,
    0x00d27f08, 0x038ab308, 0x076865c8, 0x02ad8da0, 0x024a51c4, 0x04c501dc, 0x03d3e564, 0x0163e810,
    0x0cea7f34, 0x062add5c, 0x02dc5a80, 0x02a713bc, 0x00569878, 0x0424b6c4, 0x00e51c4c, 0x022b79f0,
    0x0ba7cf00, 0x05d26020, 0x01189aa0, 0x05b71618, 0x001691c0, 0x05e34ecc, 0x01d63d9c, 0x011cd4cc,
    0x025af5ec, 0x03ccf488, 0x00d7a474, 0x016a1c94, 0x034d0c54, 0x03c431a0, 0x00ec2a00, 0x092929f4,
    0x00283888, 0x02e460d4, 0x00b7d0d8, 0x00a817f4, 0x02c9ddb0, 0x01ee0d1c, 0x011ccd3c, 0x011e812c,
    0x00f3428c, 0x009a7118, 0x00669ccc, 0x004fe9e8, 0x04a091b8, 0x02a85d2c, 0x011fb93c, 0x07a95748,
    0x07d33bc4, 0x003c5a14, 0x02856bb4, 0x00a0ebb8, 0x0162499c, 0x012fb61c, 0x0011a91c, 0x004f8390,
    0x084e8e1b, 0x02024107, 0x001f74a7, 0x011c163f, 0x0101c8a3, 0x0266106f, 0x02c359eb, 0x028a8573,
    0x00751cb3, 0x0128cd77, 0x051cc917, 0x000101e7, 0x00c45f97, 0x08808bfb, 0x00e2ddfb, 0x00ab3e97,
    0x0041f01f, 0x03c25f5f, 0x01363943, 0x0012b043, 0x02e56667, 0x0271522b, 0x0297d673, 0x010fa1c3,
    0x09a51cdf, 0x0070b4c7, 0x011d08d3, 0x034e57f7, 0x0007ac17, 0x00808b9b, 0x001bcd77, 0x00796567,
    0x00574467, 0x004a5a4b, 0x001d71cb, 0x025570fb, 0x005a08e3, 0x014c0a53, 0x02b15a87, 0x04adb977,
    0x041061c7, 0x0208858b, 0x02c8d803, 0x00421c8b, 0x030b1b3f, 0x02626d63, 0x04347af7, 0x0721d0c3,
    0x00aaef7b, 0x0224965f, 0x0043b36b, 0x00ae8957, 0x0099de1b, 0x04af4517, 0x07cb6b6f, 0x02dc98e7,
    0x0140e193, 0x007d34a3, 0x01bc3d1b, 0x06e77b8b, 0x0707f3af, 0x0976f3a7, 0x002e9027, 0x03db4bab,
    0x05c9833a, 0x066c8cd2, 0x00708e72, 0x02eb75ba, 0x008a435e, 0x004c425e, 0x035d6796, 0x016dabda,
    0x031a4d56, 0x007ea482, 0x00a43476, 0x029a1c92, 0x0418a13e, 0x0434de16, 0x09fe32ee, 0x05b902be,
    0x039f7412, 0x0042415a, 0x0052787a, 0x07df03ea, 0x05f1d512, 0x0148c766, 0x01d34356, 0x01ff0d1e,
    0x01f72e22, 0x0096c2f6, 0x01ecc1ca, 0x013727c2, 0x026893ce, 0x00899156, 0x03bf2722, 0x00a7cfee,
    0x06b78102, 0x027123ce, 0x03c5c37e, 0x03d1522a, 0x0115e54e, 0x037bef82, 0x03207d6e, 0x00425dbe,
    0x01cc201a, 0x048aa426, 0x010b76e6, 0x08b47696, 0x00613bd6, 0x00d58032, 0x0755a9f6, 0x04999252,
    0x001d3042, 0x026eb936, 0x00eddd56, 0x0f70e3de, 0x059ff73e, 0x01418bde, 0x000da462, 0x03f04f52,
    0x05bb7ea2, 0x1972ebfa, 0x0488531a, 0x011f087e, 0x020f69aa, 0x04a7583e, 0x0b1655a6, 0x008be766,
    /* 9216 bits */
    0x00d27d45, 0x150be879, 0x0410164d, 0x00ed68e1, 0x01c93c49, 0x001b18a9, 0x0323f0d1, 0x0503331d,
    0x017da375, 0x0018af0d, 0x01ae8ff5, 0x0532f5e1, 0x02ac0e4d, 0x00fb08d9, 0x043e4f49, 0x06e6c539,
    0x01c63c11, 0x013dd9c5, 0x016ed731, 0x01a6bb79, 0x0654daa5, 0x01d72ca1, 0x04652f89, 0x06d292e5,
    0x038a6119, 0x007eb8a9, 0x015ead85, 0x0092415d, 0x0093b6a5, 0x0143fd11, 0x0710e25d, 0x01c33b5d,
    0x0e0f150d, 0x031bc079, 0x076c0db5, 0x011dd1d5, 0x043d7c0d, 0x0710d031, 0x0453bba9, 0x01f171ad,
    0x012020cd, 0x01f4a699, 0x00859a49, 0x034224b9, 0x0249e931, 0x00d51b75, 0x03575745, 0x010be699,
    0x0051e911, 0x053c0031, 0x030e7585, 0x07d684ad, 0x0817ca75, 0x05314511, 0x052f7a61, 0x105cf8d9,
    0x0e8b5f51, 0x08aeee8d, 0x0382193d, 0x0095b3e9, 0x015d879d, 0x08f84fa1, 0x004b58b5, 0x008461f5,
    0x1604eb7c, 0x009f829c, 0x06c23e74, 0x050217c4, 0x0099c300, 0x035499b8, 0x0acde818, 0x00d5bab4,
    0x01958570, 0x003b2de8, 0x0091cc00, 0x08ca4c78, 0x06a68760, 0x06b6163c, 0x02c0f96c, 0x02d94ea0,
    0x0093be04, 0x0c2067f4, 0x01c68500, 0x00a6a894, 0x05030f8c, 0x00bcbb2c, 0x0382b5d8, 0x06c72ef0,
    0x01e18200, 0x03420af8, 0x066045b0, 0x01a6392c, 0x00acaef0, 0x0b74a154, 0x003c3280, 0x0992b48c,
    0x002978b8, 0x02809ac0, 0x01516f58, 0x002832a0, 0x06d01b88, 0x083f558c, 0x012e59c8, 0x024fafb8,
    0x0257541c, 0x002d1b4c, 0x00805e14, 0x08b41578, 0x04645a9c, 0x007537a8, 0x0b01a964, 0x005b1cf4,
    0x0beeed58, 0x0279c67c, 0x0223c3b4, 0x05089514, 0x03f6b09c, 0x015121ec, 0x014f5428, 0x082a8430,
    0x0aa342d4, 0x07a7de80, 0x04b1f168, 0x01888588, 0x01f30638, 0x00f1ea88, 0x017d4a84, 0x029ce8d8,
    0x03a0a453, 0x13ebb927, 0x04c869ef, 0x089e12bf, 0x012508cb, 0x006a33ab, 0x00ddb82b, 0x03feec8b,
    0x0327b03b, 0x01204a63, 0x00f98a5f, 0x01a9ad8f, 0x00c4e4a3, 0x02ac4a23, 0x048ee00f, 0x018ee71f,
    0x084a386b, 0x032d2eaf, 0x012c79a3, 0x046e5d07, 0x03a3a977, 0x0106df03, 0x09e76edb, 0x00bff9d7,
    0x00fba0db, 0x05970023, 0x0487223f, 0x06c826d7, 0x057a775f, 0x016ddaab, 0x03e22317, 0x065dbedb,
    0x02e920d3, 0x0534dc63, 0x05098727, 0x00adf0b7, 0x0141c343, 0x0269d083, 0x00519043, 0x00270dfb,
    0x06041a23, 0x0cdc8c3b, 0x0b7ff7cb, 0x00460ac7, 0x02c176c3, 0x0111c803, 0x01f8dd33, 0x0262766b,
    0x02027217, 0x004e2427, 0x0658e51f, 0x070ec25b, 0x0e5a000f, 0x050a1ef3, 0x00552b4b, 0x02ddf5bf,
    0x04e456d7, 0x087e16b7, 0x0385224f, 0x05950327, 0x046fb4e3, 0x07ab8207, 0x03edbb23, 0x0c082e5b,
    0x06648a86, 0x19ea9242, 0x065938c6, 0x0319bf02, 0x07b6263e, 0x00f5ef12, 0x001abf86, 0x02f8d5de,
    0x050eea1a, 0x011ccdee, 0x0926adfe, 0x012c716a, 0x04fb4cf2, 0x03275732, 0x036ecfba, 0x01c9e536,
    0x1a84c586, 0x00f8232e, 0x010bb5c6, 0x132190da, 0x04215b0e, 0x014d28c2, 0x01204442, 0x012cfd62,
    0x0284e9ce, 0x0143c17e, 0x0190890a, 0x00e76aae, 0x118acc82, 0x038525de, 0x1d3a417e, 0x00d7618a,
    0x04b8541e, 0x0828aa0a, 0x0192eea6, 0x07d25106, 0x011e2762, 0x003c24d2, 0x071c72da, 0x07054ec6,
    0x06187a86, 0x05490a3e, 0x09cc3ed2, 0x0ee9a27e, 0x0468b332, 0x04ae5792, 0x02e4911e, 0x03dd7396,
    0x04b923e6, 0x067324a2, 0x01304172, 0x0333621a, 0x032cf962, 0x01127552, 0x014ea46e, 0x01ede9e6,
    0x008aae02, 0x1829dd12, 0x05011712, 0x1bd469e2, 0x129ae8ce, 0x0009a652, 0x19dc0bf6, 0x010c39e2,
    0x0089a0b1, 0x01a0ed29, 0x0288b16d, 0x01068a49, 0x09acb835, 0x02ee0bf5, 0x12661299, 0x002e1c61,
    0x03511105, 0x01f6c8a5, 0x01b6605d, 0x1572512d, 0x05b710b9, 0x085614e5, 0x03df09e5, 0x02505a21,
    0x02bcb919, 0x10484b99, 0x0809ae65, 0x006e01e1, 0x0257ea05, 0x02e7586d, 0x0be78421, 0x0333fa59,
    0x0045ee8d, 0x11ee7541, 0x0177ea21, 0x037aa6cd, 0x04f3b771, 0x012e46c1, 0x0cf9c9c9, 0x0f95dbf5,
    0x01dbedb9, 0x0074cc65, 0x00bec535, 0x0007ef55, 0x02f3b3cd, 0x001d2259, 0x06a9b68d, 0x01d3977d,
    0x013b2835, 0x0989d795, 0x071b5e51, 0x01bad26d, 0x00b23299, 0x04c3db55, 0x0614819d, 0x022af3ed,
    0x010caa61, 0x0cd8c3c1, 0x025a3c5d, 0x00df0dcd, 0x055a3fe1, 0x00347459, 0x0239e589, 0x02b012e9,
    0x03d3f63d, 0x06dc5155, 0x06ce7609, 0x076bc825, 0x07d67d91, 0x07b7f125, 0x0e8a08cd, 0x04d7a7cd,
    0x01fdfae0, 0x018673dc, 0x04a46fa0, 0x05af90b8, 0x04d0b93c, 0x02fa0e6c, 0x0df92934, 0x00860380,
    0x0c9f2b70, 0x1a0b09f8, 0x02dc43d4, 0x008ba29c, 0x026d1a80, 0x0a3a1940, 0x01eb3a34, 0x079b6a8c,
    0x0a3f6970, 0x00fc0594, 0x0adf31a0, 0x0207c348, 0x004702e8, 0x02044ab0, 0x0f93a96c, 0x02b19088,
    0x0eb39670, 0x031c1f84, 0x09a3f8e0, 0x02d7d180, 0x032ca410, 0x10419b4c, 0x0393b640, 0x008315f4,
    0x0301edb0, 0x030481ec, 0x1227daf0, 0x024ae3b4, 0x01485a54, 0x0397c2b0, 0x0c9386f8, 0x047e4470,
    0x0c149dec, 0x06549368, 0x09599df0, 0x036c6b58, 0x04789ddc, 0x0eed0dd4, 0x089a6750, 0x0038b110,
    0x1078dee4, 0x05e83eb8, 0x00a27b5c, 0x05a21190, 0x00ebf36c, 0x01a6787c, 0x015361bc, 0x0ac952b4,
    0x05100ebc, 0x0a4e0ed0, 0x020f2254, 0x0283bc6c, 0x02b3c7c0, 0x0171aa08, 0x0d19adf8, 0x0d281638,
    0x095a082b, 0x0fadce5b, 0x2b6ce05b, 0x297b0f53, 0x090317e3, 0x023d779b, 0x02ddb36b, 0x03ab04c7,
    0x00f387ab, 0x03c961ff, 0x0c2583ff, 0x03acfbe3, 0x02272a47, 0x0011edcf, 0x0106735f, 0x0aa7a0e3,
    0x08912643, 0x0754e407, 0x02f23573, 0x01f75713, 0x0c1fa4db, 0x0bf37977, 0x003f57af, 0x00cbf927,
    0x00e9508f, 0x01500667, 0x0a46cf5b, 0x0618874f, 0x018b34fb, 0x00d5b89f, 0x108291b7, 0x03e49ad3,
    0x00074cbf, 0x03f76e13, 0x08c4fb6f, 0x04519dbf, 0x0367d483, 0x01685d6b, 0x00e43467, 0x05d4e25f,
    0x00862993, 0x03463493, 0x053c131b, 0x01ac3c03, 0x0b7cce0f, 0x19974957, 0x01eb28d3, 0x0014a8e7,
    0x118589af, 0x072cc7f3, 0x2a80a673, 0x016c9617, 0x04d0c7db, 0x038dd4c7, 0x0082313f, 0x13b43c4b,
    0x0dcfd5b7, 0x080966ab, 0x00e80543, 0x0703a7e7, 0x04782067, 0x0491b3cb, 0x01f2bbfb, 0x09021df3,
    0x0056e21e, 0x058188fa, 0x06e176a6, 0x060ff89e, 0x0be8c3ce, 0x0e2d8802, 0x0d7bea12, 0x0116bd32,
    0x015b30ca, 0x000ce08e, 0x27ffada6, 0x128516ba, 0x032158ea, 0x04f1c2f6, 0x026ab096, 0x0084f31a,
    0x00f6b816, 0x03f29bda, 0x0a2bcca6, 0x01e99932, 0x067fe542, 0x0538a812, 0x123e031e, 0x00406482,
    0x05f3b87a, 0x12bce96e, 0x08fcf8ee, 0x0d3a650a, 0x0f42da5a, 0x005db356, 0x0ef9f062, 0x064839da,
    0x02daf082, 0x0a4b6a3e, 0x0c84772e, 0x017194aa, 0x023eb682, 0x0e75bae6, 0x075abace, 0x15c93542,
    0x03f675ca, 0x11172f2e, 0x256cf27a, 0x063809ba, 0x08f8094e, 0x09ae51b6, 0x0b48b1ca, 0x145e5b52,
    0x121c5c5e, 0x1049b57e, 0x0deebe2e, 0x01f30a26, 0x0685a9ba, 0x02936722, 0x05bce21a, 0x08ef1e0e,
    0x032cab4a, 0x07259dbe, 0x01738c4e, 0x01745b4a, 0x02762552, 0x0879a3ea, 0x0588d00a, 0x015caf72,
    /* 13312 bits */
    0x03f59995, 0x07e8c4f5, 0x03b89625, 0x0556fae1, 0x07808d6d, 0x06e46a9d, 0x095bf719, 0x019d932d,
    0x069151fd, 0x0fc18509, 0x0300f949, 0x039da08d, 0x038e41b9, 0x122ec2e9, 0x0070bae1, 0x0675f781,
    0x01b2f6a5, 0x0f790c01, 0x0a874fb1, 0x0e8c7599, 0x0a1cede9, 0x1a4a8b01, 0x0074b231, 0x0310fc71,
    0x082e48dd, 0x2056df9d, 0x01f762fd, 0x009b1399, 0x049a538d, 0x0ddaf7dd, 0x0bd70bcd, 0x2892d1a1,
    0x036cae11, 0x00da89c9, 0x011e23f1, 0x03df9401, 0x08a753cd, 0x049862cd, 0x0018a85d, 0x3a874dcd,
    0x07aad691, 0x0f6f0eb9, 0x01e6f97d, 0x10b78de9, 0x02d75e69, 0x23f60239, 0x02020321, 0x02c8bbe1,
    0x02d353b5, 0x024b368d, 0x042ffbfd, 0x023f7681, 0x0408dc79, 0x19de5165, 0x0c8ad10d, 0x0017fe91,
    0x0c4cbbf9, 0x02b40cd1, 0x2ac66859, 0x077e0069, 0x07eb65cd, 0x045c66d1, 0x033e4f51, 0x0ee8e955,
    0x114fb87c, 0x03d008ac, 0x25318e80, 0x10486dc8, 0x086b1b64, 0x07886854, 0x028afad8, 0x0080e7f0,
    0x0648b2ac, 0x01d744d4, 0x08388930, 0x05afcbd0, 0x06772f90, 0x0d014140, 0x02ef4580, 0x08374038,
    0x0af483e4, 0x0d636f64, 0x23954d5c, 0x04a9455c, 0x1e4b0b14, 0x14a2747c, 0x0b9bbda0, 0x0405c5e8,
    0x121131f8, 0x0c833774, 0x01950f8c, 0x0d0a191c, 0x01b7e70c, 0x0754d474, 0x00080448, 0x02864d18,
    0x0210dfd0, 0x056c91f8, 0x03448168, 0x0c0fd5b4, 0x02a2932c, 0x0cf289fc, 0x026c9598, 0x00ddf534,
    0x014d2570, 0x13e4b9c8, 0x13f246d8, 0x15ed8a2c, 0x0f5cad5c, 0x07a5fc5c, 0x03194500, 0x0e7c0bc4,
    0x00f0f510, 0x10a35eb8, 0x028d960c, 0x1399d000, 0x0570d858, 0x0fa8ab1c, 0x0021515c, 0x2f6198a0,
    0x0b6c12b8, 0x0855bc68, 0x0ce80508, 0x04264bb0, 0x00590988, 0x003f75c8, 0x0698c144, 0x14e4ef50,
    0x01e8e3eb, 0x12505e0b, 0x004af827, 0x03b7da3b, 0x07b033f3, 0x0900b99f, 0x008bf28b, 0x01c966eb,
    0x11ce8dbb, 0x012d9707, 0x01325b43, 0x01167e0f, 0x02f1291b, 0x0f192727, 0x0381232f, 0x0216d6ef,
    0x070d07cb, 0x019d3087, 0x08a090bb, 0x04b70f87, 0x084279f3, 0x015cb75b, 0x0a35cb7f, 0x025be043,
    0x007f894f, 0x0fdd6d97, 0x0a36069b, 0x0c8a2453, 0x086cc8d3, 0x00344ac3, 0x02cda80b, 0x097e68cb,
    0x0dd2d683, 0x038de9c7, 0x1484c413, 0x007ac793, 0x054ea97b, 0x02b4eba3, 0x10f00c53, 0x011eb9bf,
    0x0de8e1bf, 0x02cc57f7, 0x071d0747, 0x06a4a037, 0x03fd7e4f, 0x04a42017, 0x024dab1f, 0x00056d6b,
    0x02da3603, 0x08b447a3, 0x2da7a33f, 0x03be19f3, 0x0481c05b, 0x074c570b, 0x0d5bc477, 0x01fedd9b,
    0x10cb6087, 0x0411b317, 0x0653aac7, 0x033596cb, 0x12780a6f, 0x0787901f, 0x07649433, 0x0a836747,
    0x03507712, 0x00dd5d26, 0x08f522ca, 0x008f81c6, 0x03927cce, 0x199167a6, 0x011bef32, 0x1722fb22,
    0x10983e46, 0x02e203e2, 0x162da9fa, 0x00b557d2, 0x0275920a, 0x010dea62, 0x022817aa, 0x058f635a,
    0x15823c66, 0x1131987a, 0x081a089e, 0x05305df2, 0x12fa1bb6, 0x0ddab61a, 0x00c0f462, 0x038eff22,
    0x0a8ab36a, 0x17d69b7a, 0x06a1a35e, 0x002ab56e, 0x04d7b89e, 0x15fff6aa, 0x19d82df2, 0x09e2f866,
    0x099e7b2a, 0x00e0588a, 0x23452c06, 0x04379476, 0x0278f71e, 0x0361c1ce, 0x01e956d6, 0x2f9bd976,
    0x0384faea, 0x054d481a, 0x0fc6a982, 0x015084ae, 0x024b952e, 0x0573259a, 0x08633aa6, 0x124afc2a,
    0x013a2122, 0x0158663e, 0x1e6a0b96, 0x00c9135a, 0x1f8b1d62, 0x08902c06, 0x0fcc8f1e, 0x00f76046,
    0x027fb00e, 0x03ff04da, 0x134f4f5e, 0x00b1021a, 0x0642584e, 0x02b709ca, 0x02cfa3f6, 0x01e39f62,
    0x02d6d041, 0x05f06571, 0x0df02851, 0x0adc1c81, 0x09c254d1, 0x1994c9f9, 0x0070acf1, 0x02cdf621,
    0x011a2f41, 0x0564941d, 0x02ce9355, 0x05550f91, 0x1200b651, 0x03a62f31, 0x000b9a71, 0x078531d5,
    0x0b0f5e45, 0x052da7f9, 0x036f9625, 0x08f440b9, 0x114a7d6d, 0x0f7afa4d, 0x05ccfa41, 0x0a975e2d,
    0x0ada6e91, 0x15539405, 0x095d5d59, 0x008199c5, 0x075621e1, 0x0d189c91, 0x06c18955, 0x00dbe5a5,
    0x0b37cfe1, 0x0ec8fd5d, 0x0921aa01, 0x10ada4d9, 0x09fca49d, 0x0170020d, 0x06fb8359, 0x00a644d5,
    0x09552925, 0x14f4c949, 0x01dd49bd, 0x007dc25d, 0x00dafae1, 0x05904ef9, 0x0cd6f905, 0x130de849,
    0x054b4df5, 0x007e89f5, 0x0296b301, 0x002f04c1, 0x042f32bd, 0x01a6bef1, 0x06b3e521, 0x02de8ad1,
    0x07222471, 0x0468f499, 0x1eee2565, 0x053c6c8d, 0x07bfd125, 0x002353cd, 0x0b82637d, 0x0f1afe85,
    0x067fdad4, 0x120bf0fc, 0x0184ca50, 0x0ab023f4, 0x01eb0eec, 0x11f6afb0, 0x04f45244, 0x1f4398bc,
    0x0b79c9ec, 0x1bac32b8, 0x00f2d548, 0x05c1bffc, 0x0f23ba54, 0x31e17cd0, 0x0ee91c74, 0x03345ec4,
    0x0e74375c, 0x0a6b4c00, 0x09b29360, 0x0604fab4, 0x0189a34c, 0x0468301c, 0x00cccd38, 0x1e0f337c,
    0x1e449aa4, 0x09ea69c8, 0x08758368, 0x1f3fd0b8, 0x0394123c, 0x014f5a68, 0x00c297c8, 0x0d447998,
    0x089de55c, 0x025faacc, 0x07fbce64, 0x05e3d308, 0x007c92bc, 0x0ec473ec, 0x407eea90, 0x3a10bda0,
    0x002dbb84, 0x0f776328, 0x01eb30f0, 0x006c1bfc, 0x07a30b8c, 0x164e9484, 0x006efec0, 0x0e5f1b48,
    0x08ee2f8c, 0x047c7ec8, 0x07f02a7c, 0x051782f4, 0x055a9cac, 0x0110ce64, 0x12cc8c9c, 0x117e1150,
    0x02802034, 0x1f83b7b4, 0x0a3d70f8, 0x071b7890, 0x191a77b8, 0x10434fb0, 0x03814ae4, 0x03e63774,
    0x0aa0aa4b, 
  }
};

#endif
