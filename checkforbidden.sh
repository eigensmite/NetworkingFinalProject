#!/bin/bash

FILES="chatClient2.c chatServer2.c directoryServer2.c"

FUNCS=(
    strlen
    strcat
    stpcpy
    strcpy
    strncpy
    strdup
    strcmp
    strcasecmp
    strchr
    index
    strrchr
    rindex
    strstr
    strpbrk
    strsep
    strtok
    strcspn
    strspn
    atoi
    atol
    atoll
    atof
    strtol
    strtoll
    strtoul
    strtoull
    strtof
    strtod
    strtold
    strcoll
    strfry
    strxfrm
)

for f in "${FUNCS[@]}"; do
    echo "=== Searching for: $f ==="
    grep -n --color=always -E "\b${f}\b" $FILES
    echo
done
