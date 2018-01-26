//
//  main.cpp
//  offsetfinder
//
//  Created by tihmstar on 15.09.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <iostream>
#include <string.h>
extern "C"{
#include "offsetfinder.h"
#include <libfragmentzip/libfragmentzip.h>
#include <curl/curl.h>
}
#include <libipatcher/libipatcher.hpp>
#include <vector>
#include <set>
#include <assert.h>

using namespace std;

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

set<string> found;

int doprint(char *version){
    string v{version};
    
    if (found.find(v) != found.end())
        return (fprintf(stderr, "not printing %s again\n",version),0);
    found.insert(v);
    return 1;
}

int main(int argc, const char * argv[]) {
    if (argc < 2) {
        printf("Usage: offsetfinder [kernelcache path] \n");
        return 1;
    }
    
    const char *filepath = argv[1];
    printf("[*] Found filepath: %s \n", filepath);
    
    if (access(filepath, F_OK) == -1) {
        printf("File not found: %s \n", filepath);
        return 1;
    }

    std::pair<char*,size_t> deckernel;
    FILE *kk = fopen(filepath, "rb");
    fseek(kk, 0, SEEK_END);
    deckernel.second = ftell(kk);
    fseek(kk, 0, SEEK_SET);
    deckernel.first = (char*)malloc(deckernel.second);
    fread(deckernel.first, 1, deckernel.second, kk);
    fclose(kk);
    
    macho_map_t *map = (macho_map_t *)malloc(sizeof(macho_map_t));
    map->map_data = deckernel.first;
    map->map_magic = MACHO_MAP_MAGIC;
    map->map_size = (mach_vm_size_t)deckernel.second;
    map->unique_id = (uint32_t)(((uint64_t)map << 32) >> 32);
    
    printf("[*] Finding offsets... \n");
    
    if (printKernelConfig(map,doprint))
        printf("if (0) {}\n");
    
    printf("[*] Done \n");
    
    free(map);
    
    return 0;
}
