#pragma comment(linker, "/OPT:NOWIN98")
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#pragma hdrstop

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t;

#define BSWAP16(x) (_byteswap_ushort((uint16_t)(x)))
#define BSWAP32(x) (_byteswap_ulong((uint32_t)(x)))
#define BSWAP64(x) (_byteswap_uint64((uint64_t)(x)))

__declspec(naked) unsigned short __fastcall _byteswap_ushort(unsigned short _Number)
{
	__asm {
		mov ah, cl
		mov al, ch
		ret
	}
}

__declspec(naked) unsigned long __fastcall _byteswap_ulong(unsigned long _Number)
{
	__asm {
		bswap ecx
		mov eax, ecx
		ret
	}
}

__declspec(naked) unsigned __int64 __fastcall _byteswap_uint64(unsigned __int64 _Number)
{
	__asm {
		mov edx, [esp + 4]
		mov eax, [esp + 8]
		bswap edx
		bswap eax
		ret 8
	}
}


void dump(const void *buf, size_t len)
{
	static const char hex[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
	};
	unsigned char *p, *end, c;
	char a[64];
	size_t i;

	p = (unsigned char *)buf;
	end = p + len;

	while (p < end) {
		memset(a, ' ', 64);
		i = (size_t)(end - p);
		if (i > 16) {
			i = 16;
		}
		do {
			c = p[--i];
			a[i * 3] = hex[c >> 4];
			a[i * 3 + 1] = hex[c & 15];
			if (c < 32 ||
				c > 126) {
				c = '.';
			}
			a[i + 48] = c;
		} while (i);
		p += 16;
		printf("%.*s\n", 64, a);
	}
}

void parse(const char *path)
{
	BYTE *map, *ptr;
	HANDLE h1, h2;
	uint32_t i, base_offset, files;
	uint32_t dummy, size, zsize, offset, path_sz, name_sz, temp_sz;
	uint8_t *path_ptr, *name_ptr, *temp_ptr;
	FILE *file;
	char buf[1024];

	map = NULL;

	if ((h1 = CreateFile(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) {
		if (h2 = CreateFileMapping(h1, NULL, PAGE_READONLY, 0, 0, NULL)) {
			map = MapViewOfFile(h2, FILE_MAP_READ, 0, 0, 0);
			CloseHandle(h2);
		}
		CloseHandle(h1);
	}

	if (map == NULL) {
		return;
	}

	ptr = map;

	if (*(uint32_t *)ptr != 0xBA12EC50) {
		printf("invalid magic\n");
		UnmapViewOfFile(map);
		return;
	}

	ptr += 4; // ID_STRING
	ptr += 4; // VERSION
	ptr += 4; // DUMMY
	base_offset = BSWAP32(*(uint32_t *)ptr);
	ptr += 4; // BASE_OFFSET
	files = BSWAP32(*(uint32_t *)ptr);
	ptr += 4; // FILES
	ptr += 28; // DUMMY
	
	printf("base_offset=%u, files=%u\n", base_offset, files);

	for (i = 0; i < files; ++i) {
		dummy = BSWAP32(*(uint32_t *)ptr); // 1 or 2
		ptr += 4; // DUMMY
		size = BSWAP32(*(uint32_t *)ptr);
		ptr += 4; // SIZE
		zsize = BSWAP32(*(uint32_t *)ptr);
		ptr += 4; // ZSIZE
		ptr += 8; // TIMESTAMP
		ptr += 4; // OFFSET HI
		offset = BSWAP32(*(uint32_t *)ptr);
		ptr += 4; // OFFSET LO
		if (dummy == 2) {
			ptr += 4; // DUMMY
			ptr += 4; // DUMMY
		}
		path_sz = BSWAP32(*(uint32_t *)ptr);
		ptr += 4; // PATH_SZ
		path_ptr = ptr;
		ptr += path_sz; // PATH
		name_sz = BSWAP32(*(uint32_t *)ptr);
		ptr += 4; // PATH_SZ
		name_ptr = ptr;
		ptr += name_sz; // NAME
		ptr += 4; // CRC
		ptr += 4; // DUMMY

		offset += base_offset;

		// path <-> name
		if (memchr(path_ptr, '.', path_sz)) {
			temp_sz = path_sz;
			temp_ptr = path_ptr;
			path_sz = name_sz;
			path_ptr = name_ptr;
			name_sz = temp_sz;
			name_ptr = temp_ptr;
		}

		printf("%04u: offset=%08x, path=%.*s, name=%.*s, size=%u, zsize=%u\n", i, offset, path_sz, path_ptr, name_sz, name_ptr, size, zsize);
			
		memcpy(buf, path_ptr, path_sz);
		buf[path_sz] = 0;

		temp_ptr = buf;

		for (;;) {
			temp_ptr = strchr(temp_ptr, '/');
			if (temp_ptr == NULL) {
				break;
			}
			*temp_ptr = 0;
			CreateDirectory(buf, NULL);
			*temp_ptr = '/';
			++temp_ptr;
		}

		memcpy(buf + path_sz, name_ptr, name_sz);
		buf[path_sz + name_sz] = 0;

		file = fopen(buf, "wb");
		if (file == NULL) {
			printf("fopen() failed: %s\n", buf);
			continue;
		}
		fwrite(map + offset, 1, size, file);
		fclose(file);
	}

	printf("done\n");
	UnmapViewOfFile(map);
}

int main(int argc, const char **argv)
{
	parse("C:\\Users\\mina\\Desktop\\ภ๚ดํทา\\JD2018\\DATA\\files\\bundlelogic_wii.ipk");
	parse("C:\\Users\\mina\\Desktop\\ภ๚ดํทา\\JD2018\\DATA\\files\\bundle_wii.ipk");
	parse("C:\\Users\\mina\\Desktop\\ภ๚ดํทา\\JD2018\\DATA\\files\\bundle_0_wii.ipk");
	parse("C:\\Users\\mina\\Desktop\\ภ๚ดํทา\\JD2018\\DATA\\files\\bundle_1_wii.ipk");
	parse("C:\\Users\\mina\\Desktop\\ภ๚ดํทา\\JD2018\\DATA\\files\\bundle_2_wii.ipk");
	parse("C:\\Users\\mina\\Desktop\\ภ๚ดํทา\\JD2018\\DATA\\files\\bundle_3_wii.ipk");
	parse("C:\\Users\\mina\\Desktop\\ภ๚ดํทา\\JD2018\\DATA\\files\\bundle_4_wii.ipk");
	parse("C:\\Users\\mina\\Desktop\\ภ๚ดํทา\\JD2018\\DATA\\files\\bundle_5_wii.ipk");
	parse("C:\\Users\\mina\\Desktop\\ภ๚ดํทา\\JD2018\\DATA\\files\\bundle_6_wii.ipk");
	return 0;
}