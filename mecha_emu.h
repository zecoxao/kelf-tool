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

#ifndef __MECHAEMU_H__
#define __MECHAEMU_H__

#include <memory.h>
#include <stdlib.h>
#include <inttypes.h>

int meGetContentKeyOffset(uint8_t *KelfHeader);
void meDecryptDiskContentKey(uint8_t *KelfHeader);
void meEncryptCardContentKey(uint8_t *ContentKey);

#endif

