#!/bin/bash

USERPROG_DIR="userprog"
EXAMPLES_DIR="examples"

PINTOS_RUN=$*

# Build examples (for the 'echo' prog)
  cd "src/$EXAMPLES_DIR"
  make
  cd "../$USERPROG_DIR"

# inject hex dump line
  grep "ARG_TEST_MAGIC" process.c
  STATUS="$?"
  if [ $STATUS -eq 1 ] 
  then
    sed -i '/We arrive here whether the load is successful or not./a hex_dump( (uintptr_t) *esp, *esp, PHYS_BASE-*esp, true); //ARG_TEST_MAGIC' process.c
  fi

# build userprog
  make

# cd build
  cd build

# run cmd, save output
  pintos -v -k -T 60 --qemu --filesys-size=2 -p ../../examples/cmp -a cmp -p ../../examples/cat -a cat -p ../../examples/echo -a echo -- -f -q run "$PINTOS_RUN"

# Remove sed line
  cd ../
  sed -i '/ARG_TEST_MAGIC/d' process.c

# diff output with arg_pass_test.txt
#   cd ../../pa2_arg_test/
#   grep -f arg_pass_test_out.txt arg_pass_test_gold.txt
#   STATUS="$?"
#   if [ $STATUS -eq 1 ] 
#   then
#     echo -e "\n----------------------------------------" 
#     echo "Failure! Argument passing does not work as intended."
#     echo "----------------------------------------" 
#   else
#     echo -e "\n----------------------------------------" 
#     echo "Success! Argument passing works!"
#     echo "----------------------------------------" 
#   fi
