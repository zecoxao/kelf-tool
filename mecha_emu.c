/*
 * Copyright jimmimikaelkael,balika,zecoxao
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "mecha_emu.h"
#include "util.h"
#include "cipher.h"

#include <stdio.h>

#define _CrtDbgBreak() __asm__ ("\tint $0x3\n")


struct CryptoContext {
	uint8_t UniqueKey[16];
	uint8_t FileKey[16];
	uint8_t CardIV[8];
	uint8_t CardMaterial[8];
	uint8_t CardNonce[8];
	uint8_t MechaNonce[8];
	uint8_t SessionKey[8];
	uint8_t DecryptedKbit[16];
	uint8_t DecryptedKc[16];
	uint8_t EncryptedKbit[16];
	uint8_t EncryptedKc[16];
} __attribute__((packed));

struct Kelf_Header {
	uint32_t unknown1;             
	uint32_t unknown2;
	uint16_t unknown3_half;
	uint16_t version;
	uint32_t unknown4;
	uint32_t ELF_size;		/* Size of data blocks = Decrypted elf size */
	uint16_t Kelf_header_size;	/* Kelf header size                         */
	uint16_t unknown5;
	uint16_t flags;			/* ? for header purpose                     */
	uint16_t BIT_count;		/* used to set/get kbit and kc offset       */
	uint32_t mg_zones;
} __attribute__((packed));

typedef struct {
	uint32_t length;
	uint32_t type; //3 encrypted & signed 2 signed 0 raw
	uint8_t signature[8];
} BLOCK;

static struct CryptoContext context;

/*
	PASTE PORN HERE
*/

#include "keys.h"

/*
 * meGetContentKeyOffset: calculate ContentKey offset in a kelf
 */
int meGetContentKeyOffset(uint8_t *KelfHeader)
{
	int i, offset;
	struct Kelf_Header *hdr = (struct Kelf_Header *)KelfHeader;

	offset = 32;

	for (i=0; i<read_le_uint16((uint8_t *)&hdr->BIT_count); i++)
		offset += 16;

	if ((read_le_uint32((uint8_t *)&hdr->flags) & 1) != 0)
		offset += KelfHeader[offset] + 1;

	if ((read_le_uint32((uint8_t *)&hdr->flags) & 0xf000) == 0)
		offset += 8;

	return offset;
}

void hexDump(const void *data, size_t size) {
  size_t i;
  for (i = 0; i < size; i++) {
    printf("%02hhX%c", ((char *)data)[i], (i + 1) % 16 ? ' ' : '\n');
  }
  printf("\n");
}

/*
 * meDecryptDiskContentKey: Decrypt the encrypted ContentKey for disk/rom
 * from a given Kelf header
 */
void meDecryptDiskContentKey(uint8_t *KelfHeader)
{
	int CK_offset;
	uint8_t HeaderData[8];
	uint32_t num_bitsignatures=0;
	uint8_t signatures1[0x10];
	
	uint16_t flags = read_le_uint16(KelfHeader+0x18);

	CK_offset = meGetContentKeyOffset(KelfHeader);
	
	uint8_t TheHeader[CK_offset-8];
	cipherCbcEncrypt(TheHeader, KelfHeader, CK_offset-8, MG_SIG_MASTER_KEY, 1, MG_IV_NULL);
	
	uint8_t TheHeaderSignature[8];
	memcpy(TheHeaderSignature, TheHeader + sizeof(TheHeader) - 8, 8);
	cipherCbcDecrypt(TheHeaderSignature, TheHeaderSignature, 8, MG_SIG_HASH_KEY, 1, MG_IV_NULL);
	cipherCbcEncrypt(TheHeaderSignature, TheHeaderSignature, 8, MG_SIG_MASTER_KEY, 1, MG_IV_NULL);

	if(memcmp(TheHeaderSignature,KelfHeader+CK_offset-8,8)==0){
		printf("valid header signature!\n");
		memcpy(signatures1,TheHeaderSignature,8);
	}

	/* calculate file keys necessary to decrypt Kbit and Kc from MG header */
	
	memxor(KelfHeader, &KelfHeader[8], HeaderData, 8);
	cipherCbcEncrypt(&context.FileKey[0], HeaderData, 8, MG_KBIT_MASTER_KEY, 2, MG_KBIT_MATERIAL);
	cipherCbcEncrypt(&context.FileKey[8], HeaderData, 8, MG_KC_MASTER_KEY,   2, MG_KC_MATERIAL);	

	memcpy(context.EncryptedKbit, &KelfHeader[CK_offset], 16);
	memcpy(context.EncryptedKc, &KelfHeader[CK_offset+16], 16);


	/* finally Decrypt the ContentKey */
	cipherCbcDecrypt(&context.DecryptedKbit[0], &context.EncryptedKbit[0], 8, context.FileKey, 2, MG_IV_NULL);
	cipherCbcDecrypt(&context.DecryptedKbit[8], &context.EncryptedKbit[8], 8, context.FileKey, 2, MG_IV_NULL);
	cipherCbcDecrypt(&context.DecryptedKc[0],   &context.EncryptedKc[0],   8, context.FileKey, 2, MG_IV_NULL);
	cipherCbcDecrypt(&context.DecryptedKc[8],   &context.EncryptedKc[8],   8, context.FileKey, 2, MG_IV_NULL);

	memcpy(&KelfHeader[CK_offset], context.DecryptedKbit , 16);
	memcpy(&KelfHeader[CK_offset+16], context.DecryptedKc , 16);

	cipherCbcDecrypt(KelfHeader + CK_offset + 0x20, KelfHeader + CK_offset + 0x20, 8, &context.DecryptedKbit[0], 2, MG_IV_CONTENT_TABLE);
	
	uint32_t data_start = read_le_uint32(KelfHeader + CK_offset + 0x20);
	uint32_t num_blocks = read_le_uint32(KelfHeader + CK_offset + 0x24);
	
	cipherCbcEncrypt(KelfHeader + CK_offset + 0x20, KelfHeader + CK_offset + 0x20, 8 ,&context.DecryptedKbit[0], 2, MG_IV_CONTENT_TABLE);
	cipherCbcDecrypt(KelfHeader + CK_offset + 0x20, KelfHeader + CK_offset + 0x20, 8 + (0x10 * num_blocks), &context.DecryptedKbit[0], 2, MG_IV_CONTENT_TABLE);

	int i = 0;
	int total_length=0;
	
	uint8_t hash[8];
	memcpy(hash, &context.DecryptedKbit[0], 8);
	if (memcmp(&context.DecryptedKbit[0], &context.DecryptedKbit[8], 8) != 0){
		memxor(&context.DecryptedKbit[8], hash, hash, 8);
	}

	memxor(&context.DecryptedKc[0], hash, hash, 8);
	if (memcmp(&context.DecryptedKc[0], &context.DecryptedKc[8], 8) != 0){
		memxor(&context.DecryptedKc[8], hash, hash, 8);
	}
	
	uint8_t bitTable[num_blocks*0x10+8];
	memcpy(bitTable,KelfHeader + CK_offset + 0x20,num_blocks*0x10+8);
	
	for (int i = 0; i < num_blocks * 2 + 1; i++){
		memxor(&((uint8_t*)& bitTable)[i * 8], hash, hash, 8);
	}
	
	uint8_t MG_SIG_MASTER_AND_HASH_KEY[16];
	memcpy(MG_SIG_MASTER_AND_HASH_KEY, MG_SIG_MASTER_KEY, 8);
	memcpy(MG_SIG_MASTER_AND_HASH_KEY + 8, MG_SIG_HASH_KEY, 8);

	uint8_t signature[8];
	cipherCbcEncrypt(signature, hash, 8, MG_SIG_MASTER_AND_HASH_KEY, 2, MG_IV_NULL);
	
	if(memcmp(KelfHeader + data_start - 0x10,signature,8)==0){
		printf("bit signature valid!\n");
		memcpy(signatures1+8,signature,8);
	}else{
		hexDump(signature,8);
		hexDump(KelfHeader + data_start - 0x10, 8);
	}
	
	for(i=0;i<num_blocks;i++){
		BLOCK * block = (BLOCK*)(KelfHeader + CK_offset + 0x20 + 8 + (0x10 * i));
		if(block->type & 2){
			uint8_t signature[8];
			memset(signature, 0, 8);
			
			num_bitsignatures++;
			
			if(block->type & 1){
			
				if (flags == 0x21C){
					cipherCbcDecrypt(KelfHeader + data_start + total_length, KelfHeader + data_start + total_length, block->length, &context.DecryptedKc[0], 1, MG_IV_BLOCK);
					
					
					
					
					for (int j = 0; j < block->length; j += 8){
						memxor(KelfHeader + data_start + total_length + j, signature, signature, 8);
					}
				
					uint8_t MG_SIG_MASTER_AND_HASH_KEY[16];
					memcpy(MG_SIG_MASTER_AND_HASH_KEY, MG_SIG_MASTER_KEY, 8);
					memcpy(MG_SIG_MASTER_AND_HASH_KEY + 8, MG_SIG_HASH_KEY, 8);
					
					cipherCbcEncrypt(signature, signature, 8, MG_SIG_MASTER_AND_HASH_KEY, 2, MG_IV_NULL);
				
					if (memcmp(block->signature, signature, 8) == 0){
						printf("valid signature!\n");
					}else{
						hexDump(block->signature,8);
						hexDump(signature,8);
					}
				}
				else if (flags == 0x22C){
					cipherCbcDecrypt(KelfHeader + data_start + total_length, KelfHeader + data_start + total_length, block->length, &context.DecryptedKc[0], 2, MG_IV_BLOCK);
					
					uint8_t signature[8];
					memset(signature, 0, 8);
					
					
					for (int j = 0; j < block->length; j += 8){
						memxor(KelfHeader + data_start + total_length + j, signature, signature, 8);
					}
				
					uint8_t MG_SIG_MASTER_AND_HASH_KEY[16];
					memcpy(MG_SIG_MASTER_AND_HASH_KEY, MG_SIG_MASTER_KEY, 8);
					memcpy(MG_SIG_MASTER_AND_HASH_KEY + 8, MG_SIG_HASH_KEY, 8);
					
					cipherCbcEncrypt(signature, signature, 8, MG_SIG_MASTER_AND_HASH_KEY, 2, MG_IV_NULL);
				
					if (memcmp(block->signature, signature, 8) == 0){
						printf("valid signature!\n");
					}else{
						hexDump(block->signature,8);
						hexDump(signature,8);
					}
				}
			}
		}
		total_length=total_length+block->length;
	}
	uint8_t signatures2[num_bitsignatures*8];
	uint8_t signatures3[sizeof(signatures1)+sizeof(signatures2)];
	

	int j = 0;
	for (int i = 0; i < num_blocks; i++){
		
		BLOCK * block = (BLOCK*)(KelfHeader + CK_offset + 0x20 + 8 + (0x10 * i));
		if(block->type & 2){
			memcpy(signatures2+j*8,block->signature,8);
			j++;
		}
		
	}
	
	memcpy(signatures3,signatures1,0x10);
	memcpy(signatures3+0x10,signatures2,num_bitsignatures*8);
	
	//hexDump(signatures3,sizeof(signatures3));
	
	cipherCbcEncrypt(signatures3, signatures3, sizeof(signatures3), MG_ROOTSIG_MASTER_KEY, 1, MG_IV_NULL);
	
	uint8_t ROOT [8];
	
	cipherCbcDecrypt(ROOT, &signatures3[sizeof(signatures3) - 8], 8, MG_ROOTSIG_HASH_KEY, 2, MG_IV_NULL);
	
	if(memcmp(ROOT,KelfHeader + data_start - 8,8)==0){
		printf("root signature valid!\n");
	}else{
		hexDump(ROOT,8);
		hexDump(KelfHeader + data_start - 8,8);
	}
}

/*
 * meEncryptCardContentKey: encrypt the decrypted ContentKey for Memory Card
 */
void meEncryptCardContentKey(uint8_t *ContentKey)
{
	cipherCbcEncrypt(&context.EncryptedKbit[0], &context.DecryptedKbit[0], 8, context.SessionKey, 1, MG_IV_NULL);
	cipherCbcEncrypt(&context.EncryptedKbit[8], &context.DecryptedKbit[8], 8, context.SessionKey, 1, MG_IV_NULL);
	cipherCbcEncrypt(&context.EncryptedKc[0],   &context.DecryptedKc[0],   8, context.SessionKey, 1, MG_IV_NULL);
	cipherCbcEncrypt(&context.EncryptedKc[8],   &context.DecryptedKc[8],   8, context.SessionKey, 1, MG_IV_NULL);

	memcpy(&ContentKey[0], context.EncryptedKbit, 16);
	memcpy(&ContentKey[16], context.EncryptedKc, 16);
}

