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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <inttypes.h>

#include "mecha_emu.h"

/*
 * meDecryptDiskContentKey: Decrypt the encrypted ContentKey for disk/rom
 * from a given Kelf header
 */
//void meDecryptDiskContentKey(uint8_t *KelfHeader)

int main(int argc, char** argv){
	if(argc < 3){
		printf("Usage: %s [kelf] [kelf.dec] \n", argv[0]);
		return 1;
	}
	
	FILE * fin = fopen(argv[1],"rb");
	fseek(fin, 0, SEEK_END);
	unsigned long fsize = ftell(fin);
	fseek(fin, 0, SEEK_SET);  /* same as rewind(f); */

	unsigned char *buf = malloc(fsize + 1);
	fread(buf, 1, fsize, fin);
	fclose(fin);
	
	meDecryptDiskContentKey(buf);

	FILE * fout = fopen(argv[2],"wb");
	fwrite(buf,1,fsize,fout);
	fclose(fout);
	
	free(buf);
	
	return 0;
}
